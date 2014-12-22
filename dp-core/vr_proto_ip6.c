/*
 * vr_proto_ip6.c -- ip6 handler
 *
 * Copyright (c) 2014, Juniper Networks, Inc.
 * All rights reserved
 */
#include <vr_os.h>
#include <vr_types.h>
#include <vr_packet.h>

#include <vr_datapath.h>
#include <vr_ip_mtrie.h>

#define SOURCE_LINK_LAYER_ADDRESS_OPTION    1
#define TARGET_LINK_LAYER_ADDRESS_OPTION    2

struct vr_neighbor_option {
    uint8_t vno_type;
    uint8_t vno_length;
    uint8_t vno_value[0];
} __attribute__((packed));

/*
 * buffer is pointer to ip6 header, all values other than src, dst and
 * plen are ZERO. bytes is total length of ip6 header, icmp header and
 * icmp option
 */
uint16_t
vr_icmp6_checksum(void *buffer, unsigned int bytes)
{
   uint32_t total;
   uint16_t *ptr;
   int num_words;

   total = 0;
   ptr   = (uint16_t *)buffer;
   num_words = (bytes + 1) / 2;

   while (num_words--)
       total += *ptr++;

   /*
    *   Fold in any carries
    *   - the addition may cause another carry so we loop
    */
   while (total & 0xffff0000)
       total = (total >> 16) + (total & 0xffff);

   return (uint16_t)total;
}

static mac_response_t
vr_neighbor_response_type(unsigned short vrf, struct vr_packet *pkt,
        struct vr_icmp *icmph)
{
    uint32_t rt_prefix[4];

    struct vr_route_req rt;
    struct vr_nexthop *nh;

    rt.rtr_req.rtr_vrf_id = vrf;
    rt.rtr_req.rtr_family = AF_INET6;
    rt.rtr_req.rtr_prefix = (uint8_t *)&rt_prefix;
    memcpy(rt.rtr_req.rtr_prefix, icmph->icmp_data, 16);
    rt.rtr_req.rtr_prefix_size = 16;
    rt.rtr_req.rtr_prefix_len = IP6_PREFIX_LEN;
    rt.rtr_req.rtr_nh_id = 0;
    rt.rtr_req.rtr_label_flags = 0;

    nh = vr_inet_route_lookup(vrf, &rt);
    if (!nh)
        return MR_NOT_ME;

    if (rt.rtr_req.rtr_label_flags & VR_RT_ARP_PROXY_FLAG)
        return MR_PROXY;

    switch (nh->nh_type) {
    case NH_TUNNEL:
        return MR_PROXY;

    case  NH_COMPOSITE:
        if ((nh->nh_flags & NH_FLAG_COMPOSITE_EVPN) ||
                (nh->nh_flags & NH_FLAG_COMPOSITE_L2)) {
            pkt->vp_nh = nh;
            return MR_FLOOD;
        }
        break;

    default:
        break;
    }

    return MR_NOT_ME;
}

static void
vr_icmp6_neighbor_input(struct vrouter *router, unsigned short vrf,
        struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    uint16_t *eth_proto;
    mac_response_t type;

    struct vr_interface *vif = pkt->vp_if;

    struct vr_neighbor_option *nopt;
    struct vr_ip6 *ip6 = (struct vr_ip6 *)pkt_network_header(pkt);
    struct vr_icmp *icmph = (struct vr_icmp *)pkt_data(pkt);
    struct vr_eth *eth;

    type = vr_neighbor_response_type(vrf, pkt, icmph);
    switch (type) {
    case MR_FLOOD:
        vr_preset(pkt);
        nh_output(vrf, pkt, pkt->vp_nh, fmd);
        return;

    case MR_PROXY:
        break;

    case MR_NOT_ME:
    default:
        vr_pfree(pkt, VP_DROP_ARP_NO_WHERE_TO_GO);
        return;
    }

    memcpy(ip6->ip6_dst, ip6->ip6_src, sizeof(ip6->ip6_src));
    memcpy(ip6->ip6_src, &icmph->icmp_data, sizeof(ip6->ip6_src));
    /* Mimic a different source ip */
    ip6->ip6_src[15] = 0xFF;

    /* Update ICMP header and options */
    icmph->icmp_type = VR_ICMP6_TYPE_NEIGH_AD;
    icmph->icmp_eid = htons(0x4000);
    nopt = (struct vr_neighbor_option *)(icmph->icmp_data +
            VR_IP6_ADDRESS_LEN);
    nopt->vno_type = TARGET_LINK_LAYER_ADDRESS_OPTION;
    /* length in units of 8 octets */
    nopt->vno_length = (sizeof(struct vr_neighbor_option) + VR_ETHER_ALEN) / 8;
    memcpy(nopt->vno_value, vif->vif_mac, VR_ETHER_ALEN);

    icmph->icmp_csum =
        ~(vr_icmp6_checksum(ip6, sizeof(struct vr_ip6) +
                    sizeof(struct vr_icmp) + VR_IP6_ADDRESS_LEN +
                    nopt->vno_length));

    vr_preset(pkt);
    eth = (struct vr_eth *)pkt_data(pkt);
    /* Update Ethernet headr */
    memcpy(eth->eth_dmac, eth->eth_smac, VR_ETHER_ALEN);
    memcpy(eth->eth_smac, vif->vif_mac, VR_ETHER_ALEN);
    eth_proto = &eth->eth_proto;
    if (vif_is_vlan(vif)) {
        if (vif->vif_ovlan_id) {
            *eth_proto = htons(VR_ETH_PROTO_VLAN);
            eth_proto++;
            *eth_proto = htons(vif->vif_ovlan_id);
            eth_proto++;
        }
    }
    *eth_proto = htons(VR_ETH_PROTO_IP6);
    /* Respond back directly*/
    vif->vif_tx(vif, pkt);

    return;
}


static bool
vr_icmp6_input(struct vrouter *router, unsigned short vrf,
        struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    bool handled = true;
    struct vr_icmp *icmph;

    icmph = (struct vr_icmp *)pkt_data(pkt);
    switch (icmph->icmp_type) {
    case VR_ICMP6_TYPE_NEIGH_SOL:
        vr_icmp6_neighbor_input(router, vrf, pkt, fmd);
        break;

    case VR_ICMP6_TYPE_ROUTER_SOL:
        vr_trap(pkt, vrf, AGENT_TRAP_L3_PROTOCOLS, NULL);
        break;

    default:
        handled = false;
        break;
    }

    return handled;
}

int
vr_ip6_input(struct vrouter *router, unsigned short vrf,
        struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    struct vr_ip6 *ip6;
    unsigned short *t_hdr, sport, dport;

    ip6 = (struct vr_ip6 *)pkt_network_header(pkt);
    t_hdr = (unsigned short *)((char *)ip6 + sizeof(struct vr_ip6));

    if (!pkt_pull(pkt, sizeof(struct vr_ip6))) {
        vr_pfree(pkt, VP_DROP_PULL);
        return 0;
    }

    switch (ip6->ip6_nxt) {
    case VR_IP_PROTO_ICMP6:
        if (vr_icmp6_input(router, vrf, pkt, fmd))
            return 0;
        break;

    case VR_IP_PROTO_UDP:
        sport = *t_hdr;
        dport = *(t_hdr + 1);
        if (vif_is_virtual(pkt->vp_if)) {
            if ((sport == VR_DHCP6_SPORT) && (dport == VR_DHCP6_DPORT))
                return vr_trap(pkt, vrf, AGENT_TRAP_L3_PROTOCOLS, NULL);
        }
        break;

    default:
        break;
    }

    if (!pkt_push(pkt, sizeof(struct vr_ip6))) {
        vr_pfree(pkt, VP_DROP_PUSH);
        return 0;
    }

    return vr_forward(router, vrf, pkt, fmd);
}
