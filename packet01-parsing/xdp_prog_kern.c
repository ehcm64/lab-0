/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

/* Header cursor to keep track of current parsing position */
struct hdr_cursor
{
	void *pos;
};

struct vlan_hdr
{
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH 2
#endif

#define VLAN_VID_MASK 0x0fff /* VLAN Identifier */
/* Struct for collecting VLANs after parsing via parse_ethhdr_vlan */
struct collect_vlans
{
	__u16 id[VLAN_MAX_DEPTH];
};

static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
			  h_proto == bpf_htons(ETH_P_8021AD));
}

/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */
static __always_inline int parse_ethhdr_vlan(struct hdr_cursor *nh,
											 void *data_end,
											 struct ethhdr **ethhdr,
											 struct collect_vlans *vlans)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);
	struct vlan_hdr *vlh;
	__u16 h_proto;
	int i;

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;
	vlh = nh->pos;
	h_proto = eth->h_proto;

/* Use loop unrolling to avoid the verifier restriction on loops;
 * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
 */
#pragma unroll
	for (i = 0; i < VLAN_MAX_DEPTH; i++)
	{
		if (!proto_is_vlan(h_proto))
			break;

		if (vlh + 1 > data_end)
			break;

		h_proto = vlh->h_vlan_encapsulated_proto;
		if (vlans) /* collect VLAN ids */
			vlans->id[i] =
				(bpf_ntohs(vlh->h_vlan_TCI) & VLAN_VID_MASK);

		vlh++;
	}

	nh->pos = vlh;
	return h_proto; /* network-byte-order */
}

static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
										void *data_end,
										struct ethhdr **ethhdr)
{
	return parse_ethhdr_vlan(nh, data_end, ethhdr, NULL);
}

/* Assignment 2: Implement and use this */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
										void *data_end,
										struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *hdr = nh->pos;

	if (hdr + 1 > data_end)
		return -1;

	nh->pos += sizeof(*hdr);
	*ip6hdr = hdr;

	return hdr->nexthdr;
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
									   void *data_end,
									   struct iphdr **iphdr)
{
	struct iphdr *hdr = nh->pos;
	int hdrsize;

	if (hdr + 1 > data_end)
		return -1;

	hdrsize = hdr->ihl * 4;
	/* Sanity check packet field is valid */
	if (hdrsize < sizeof(*hdr))
		return -1;

	/* Variable-length IPv4 header, need to use byte-based arithmetic */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*iphdr = hdr;

	return hdr->protocol;
}

/* Assignment 3: Implement and use this */
static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
										  void *data_end,
										  struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *hdr = nh->pos;

	if (hdr + 1 > data_end)
		return -1;

	nh->pos += sizeof(*hdr);
	*icmp6hdr = hdr;

	return hdr->icmp6_type;
}

static __always_inline int parse_icmphdr(struct hdr_cursor *nh,
										 void *data_end,
										 struct icmphdr **icmphdr)
{
	struct icmphdr *hdr = nh->pos;

	if (hdr + 1 > data_end)
		return -1;

	nh->pos += sizeof(*hdr);
	*icmphdr = hdr;

	return hdr->type;
}


SEC("xdp")
int xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
	struct ipv6hdr *ipv6hdr;
	struct iphdr *iphdr;
	struct icmp6hdr *icmp6hdr;
	struct icmphdr *icmphdr;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type != bpf_htons(ETH_P_IPV6)) {
		action = XDP_ABORTED;
		goto out;
	}

	int ip_type, icmp_type;

	if (nh_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
	} else if (nh_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
	} else {
		action = XDP_ABORTED;
		goto out;
	}

	if (ip_type == bpf_htons(IPPROTO_ICMP)) {
		icmp_type = parse_icmphdr(&nh, data_end, &icmphdr);
		if (icmp_type == bpf_htons(ICMP_ECHO) 
		&& (bpf_ntohs(icmphdr->un.echo.sequence) % 2 == 0)) {
			action = XDP_DROP;
			goto out;
		}
	} else if (ip_type == bpf_htons(IPPROTO_ICMPV6)) {
		icmp_type = parse_icmp6hdr(&nh, data_end, &icmp6hdr);
		if (icmp_type == bpf_htons(ICMP_ECHO)
		&& (bpf_ntohs(icmp6hdr->icmp6_dataun.u_echo.sequence) % 2 == 0)) {
			action = XDP_DROP;
			goto out;
		}
	} else {
		goto out;
	}
		/* Assignment additions go below here */

		action = XDP_DROP;
out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
