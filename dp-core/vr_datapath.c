/*
 * vr_datapath.c -- data path inside the router
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_bridge.h>
#include <vr_datapath.h>
#include <vr_packet.h>
#include <vr_mirror.h>
#include <vr_bridge.h>

extern unsigned int vr_inet_route_flags(unsigned int, unsigned int);
extern struct vr_vrf_stats *(*vr_inet_vrf_stats)(unsigned short,
                                                 unsigned int);


static inline bool
vr_grat_arp(struct vr_arp *sarp)
{
    if (sarp->arp_spa == sarp->arp_dpa)
        return true;
    return false;
}

static int 
vr_v6_prefix_is_ll(uint8_t prefix[])  
{
    if ((prefix[0] == 0xFE) && (prefix[1] == 0x80)) {
        return true;
    }
    return false;
}

static int
vr_arp_request_treatment(unsigned short vrf, struct vr_packet *pkt,
                         struct vr_arp *arp, char *src_mac, int pkt_src,
                         int *drop_reason)
{
    struct vr_route_req rt;
    struct vr_nexthop *nh;
    uint32_t rt_prefix;
    bool grat_arp;
    struct vr_vrf_stats *stats;
    struct vr_interface *vif = pkt->vp_if;

    stats = vr_inet_vrf_stats(vrf, pkt->vp_cpu);

    *drop_reason = VP_DROP_INVALID_ARP;
    if (vif_mode_xconnect(vif))
        return PKT_ARP_XCONNECT;

    if (vif_is_virtual(vif))
        /*
         * some OSes send arp queries with zero SIP before taking ownership
         * of the DIP
         */
        if (!arp->arp_spa)
            return PKT_ARP_DROP;

    if (vif->vif_type == VIF_TYPE_XEN_LL_HOST ||
            vif->vif_type == VIF_TYPE_GATEWAY)
        goto proxy;

    /* All link local IP's have to be proxied */
    if (vif->vif_type == VIF_TYPE_HOST) {
        if (IS_LINK_LOCAL_IP(arp->arp_dpa))
            goto proxy;
    }

    grat_arp = vr_grat_arp(arp);

    /*
     * Grat ARP from Fabric need to be cross connected to Vhost
     * and Flooded Flooded if received from another compute node
     * or BMS
     */
    if (grat_arp && (vif->vif_type == VIF_TYPE_PHYSICAL)) {
        if (!pkt_src)
            return PKT_ARP_TRAP_XCONNECT;
        else
            return PKT_ARP_FLOOD;
    }

    memset(&rt, 0, sizeof(rt));
    rt.rtr_req.rtr_vrf_id = vrf;
    rt.rtr_req.rtr_prefix = (uint8_t*)&rt_prefix;
    *(uint32_t*)rt.rtr_req.rtr_prefix = (arp->arp_dpa);
    rt.rtr_req.rtr_prefix_size = 4;
    rt.rtr_req.rtr_prefix_len = 32;

    vr_inet_route_get(vrf, &rt);

    if (vif_is_virtual(vif)) {

        /*
         * Grat ARP from VM need to be Trapped to Agent if Trap Set
         * else need to be flooded
         */
        if (grat_arp) {
            if (rt.rtr_req.rtr_label_flags & VR_RT_ARP_TRAP_FLAG)
                return PKT_ARP_TRAP;
            else
                return PKT_ARP_FLOOD;
        }

        /*
         * Request from VM:
         * If Proxy Bit Set -
         *    - If stitched : Proxy with Stitched MAC
         *    - If not stitched : Proxy with VIF's Mac
         * If no route is found : Drop the request
         * IF route is found and not proxied : Flood
         *
         */
        if (rt.rtr_req.rtr_label_flags & VR_RT_PROXY_FLAG) {
            if (!(rt.rtr_req.rtr_label_flags & VR_RT_BRIDGE_ENTRY_FLAG)) {
                if (stats)
                    stats->vrf_arp_virtual_proxy++;
                goto proxy;
            }

            rt.rtr_req.rtr_index = rt.rtr_req.rtr_nh_id;
            rt.rtr_req.rtr_mac = src_mac;
            if (vr_bridge_lookup(vrf, &rt)) {
                if (stats)
                    stats->vrf_arp_virtual_stitch++;
                goto stitch;
            }
        }

        /* If there is no route found, lets drop the ARP request */
        if ((!rt.rtr_nh) || (rt.rtr_nh->nh_type == NH_DISCARD)) {
            *drop_reason = VP_DROP_ARP_NO_ROUTE;
            return PKT_ARP_DROP;
        }

        if (stats)
            stats->vrf_arp_virtual_flood++;
        return PKT_ARP_FLOOD;
    }

    if (vif->vif_type == VIF_TYPE_HOST)
        return PKT_ARP_XCONNECT;

    /*
     * Request from Physical:
     * If from Fabric n/w : Proxy
     * if Proxy bit  set:
     *  - If the VM is hosted on this node (Encap NH) : Proxy with VM's MAC
     *  - If from Tor, meant for DNS server (Rcv NH) : Proy with VIF's MAC
     *  - else : Flood
     */
    if (vif->vif_type == VIF_TYPE_PHYSICAL) {
        if (!pkt_src) {
            if (rt.rtr_req.rtr_label_flags & VR_RT_PROXY_FLAG) {
                goto proxy;
            }
        } else {
            if (rt.rtr_req.rtr_label_flags & VR_RT_PROXY_FLAG) {
                if (rt.rtr_req.rtr_label_flags & VR_RT_BRIDGE_ENTRY_FLAG) {
                    rt.rtr_req.rtr_index = rt.rtr_req.rtr_nh_id;
                    rt.rtr_req.rtr_mac = src_mac;
                    if ((nh = vr_bridge_lookup(vrf, &rt))) {
                        if (nh->nh_type == NH_ENCAP) {
                            if (stats)
                                stats->vrf_arp_physical_stitch++;
                            goto stitch;
                        }
                    }
                } else {
                    nh = rt.rtr_nh;
                    if (pkt_src == PKT_SRC_TOR_REPL_TREE) {
                        if (nh->nh_type == NH_RCV) {
                            if (stats)
                                stats->vrf_arp_tor_proxy++;
                            goto proxy;
                        }
                    }
                }
            }
            if (stats)
                stats->vrf_arp_physical_flood++;
            return PKT_ARP_FLOOD;
        }
    }

    *drop_reason = VP_DROP_ARP_NO_WHERE_TO_GO;
    return PKT_ARP_DROP;

proxy:
    VR_MAC_COPY(src_mac, vif->vif_mac);
stitch:
    return PKT_ARP_PROXY;
}

static int
vr_handle_arp_request(unsigned short vrf, struct vr_arp *sarp,
                      struct vr_packet *pkt, struct vr_forwarding_md *fmd,
                      int pkt_src)
{
    struct vr_packet *cloned_pkt;
    struct vr_interface *vif = pkt->vp_if;
    struct vr_eth *eth;
    struct vr_arp *arp;
    unsigned int dpa;
    int arp_result, drop_reason;
    struct vr_route_req rt;
    char arp_src_mac[VR_ETHER_ALEN];
    struct vr_nexthop *nh;

    arp_result = vr_arp_request_treatment(vrf, pkt, sarp, arp_src_mac,
                                          pkt_src, &drop_reason);
    switch (arp_result) {
    case PKT_ARP_PROXY:

        memset(&rt, 0, sizeof(rt));
        rt.rtr_req.rtr_vrf_id = vrf;

        if ((vif->vif_type == VIF_TYPE_HOST) ||
                ((vif->vif_type == VIF_TYPE_PHYSICAL) && (!pkt_src))) {

            rt.rtr_req.rtr_prefix = (uint8_t*)&dpa;
            *(uint32_t*)rt.rtr_req.rtr_prefix = (sarp->arp_spa);
            rt.rtr_req.rtr_prefix_size = 4;
            rt.rtr_req.rtr_prefix_len = 32;

            nh = vr_inet_route_lookup(vrf, &rt);
            if ((!nh) || ((nh->nh_type != NH_ENCAP) &&
                    (nh->nh_type != NH_RCV) && (nh->nh_type != NH_RESOLVE))) {
                vr_pfree(pkt, VP_DROP_ARP_REPLY_NO_ROUTE);
                return 1;
            }
        } else {
            rt.rtr_req.rtr_mac_size = VR_ETHER_ALEN;
            rt.rtr_req.rtr_mac = sarp->arp_sha;
            if (!vr_bridge_lookup(vrf, &rt)) {
                vr_pfree(pkt, VP_DROP_ARP_REPLY_NO_ROUTE);
                return 1;
            }
            nh = rt.rtr_nh;
            if ((!nh) || ((nh->nh_type != NH_ENCAP) &&
                    (nh->nh_type != NH_TUNNEL))) {
                vr_pfree(pkt, VP_DROP_ARP_REPLY_NO_ROUTE);
                return 1;
            }
            if (rt.rtr_req.rtr_label_flags & VR_RT_LABEL_VALID_FLAG)
                fmd->fmd_label = rt.rtr_req.rtr_label;
        }

        pkt_reset(pkt);

        eth = (struct vr_eth *)pkt_data(pkt);
        memcpy(eth->eth_dmac, sarp->arp_sha, VR_ETHER_ALEN);
        memcpy(eth->eth_smac, arp_src_mac, VR_ETHER_ALEN);
        eth->eth_proto = htons(VR_ETH_PROTO_ARP);

        arp = (struct vr_arp *)pkt_pull_tail(pkt, VR_ETHER_HLEN);

        sarp->arp_op = htons(VR_ARP_OP_REPLY);
        memcpy(sarp->arp_sha, arp_src_mac, VR_ETHER_ALEN);
        memcpy(sarp->arp_dha, eth->eth_dmac, VR_ETHER_ALEN);
        dpa = sarp->arp_dpa;
        memcpy(&sarp->arp_dpa, &sarp->arp_spa, sizeof(sarp->arp_dpa));
        memcpy(&sarp->arp_spa, &dpa, sizeof(sarp->arp_spa));

        memcpy(arp, sarp, sizeof(*sarp));
        pkt_pull_tail(pkt, sizeof(*arp));

        nh->nh_arp_response(vrf, pkt, nh, fmd);
        break;
    case PKT_ARP_XCONNECT:
        vif_xconnect(vif, pkt);
        break;
    case PKT_ARP_TRAP_XCONNECT:
        cloned_pkt = vr_pclone(pkt);
        if (cloned_pkt) {
            vr_preset(cloned_pkt);
            vif_xconnect(vif, cloned_pkt);
        }
        vr_trap(pkt, vrf, AGENT_TRAP_ARP, NULL);
        break;
    case PKT_ARP_TRAP:
        vr_preset(pkt);
        vr_trap(pkt, vrf, AGENT_TRAP_ARP, NULL);
        break;
    case PKT_ARP_FLOOD:
        return 0;
    case PKT_ARP_DROP:
    default:
        vr_pfree(pkt, drop_reason);
    }

    return 1;
}

/*
 * arp responses from vhostX need to be cross connected. nothing
 * needs to be done for arp responses from VMs, while responses
 * from fabric needs to be Xconnected and sent to agent
 */
static int
vr_handle_arp_reply(unsigned short vrf, struct vr_arp *sarp,
                    struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    struct vr_interface *vif = pkt->vp_if;
    struct vr_packet *cloned_pkt;

    if (vif_mode_xconnect(vif) || vif->vif_type == VIF_TYPE_HOST)
        return vif_xconnect(vif, pkt);

    if (vif->vif_type != VIF_TYPE_PHYSICAL) {
        if (vif_is_virtual(vif)) {
            vr_preset(pkt);
            return vr_trap(pkt, vrf, AGENT_TRAP_ARP, NULL);
        }
        vr_pfree(pkt, VP_DROP_INVALID_IF);
        return 0;
    }


    cloned_pkt = vr_pclone(pkt);
    if (cloned_pkt) {
        vr_preset(cloned_pkt);
        vif_xconnect(vif, cloned_pkt);
    }

    return vr_trap(pkt, vrf, AGENT_TRAP_ARP, NULL);
}

/*
 * This funciton parses the ethernet packet and assigns the
 * pkt->vp_type, network protocol of the packet. The ethernet header can
 * start from an offset from vp_data
 */
int
vr_pkt_type(struct vr_packet *pkt, unsigned short offset)
{
    unsigned char *eth = pkt_data(pkt) + offset;
    unsigned short eth_proto;
    int pull_len, pkt_len = pkt_head_len(pkt) - offset;
    struct vr_vlan_hdr *vlan;

    pull_len = VR_ETHER_HLEN;
    if (pkt_len < pull_len)
        return -1;

    pkt->vp_flags &= ~(VP_FLAG_MULTICAST);

    /* L2 broadcast/multicast packets are multicast packets */
    if (IS_MAC_BMCAST(eth))
        pkt->vp_flags |= VP_FLAG_MULTICAST;

    eth_proto = ntohs(*(unsigned short *)(eth + VR_ETHER_PROTO_OFF));
    while (eth_proto == VR_ETH_PROTO_VLAN) {
        if (pkt_len < (pull_len + sizeof(*vlan)))
            return -1;
        vlan = (struct vr_vlan_hdr *)(eth + pull_len);
        eth_proto = ntohs(vlan->vlan_proto);
        pull_len += sizeof(*vlan);
    }


    pkt_set_network_header(pkt, pkt->vp_data + offset + pull_len);
    pkt_set_inner_network_header(pkt, pkt->vp_data + offset + pull_len);
    pkt->vp_type = vr_eth_proto_to_pkt_type(eth_proto);

    return 0;
}

int
vr_arp_input(unsigned short vrf, struct vr_packet *pkt,
             struct vr_forwarding_md *fmd, int pkt_src)
{
    struct vr_arp sarp;

    memcpy(&sarp, pkt_data(pkt), sizeof(struct vr_arp));
    switch (ntohs(sarp.arp_op)) {
    case VR_ARP_OP_REQUEST:
        return vr_handle_arp_request(vrf, &sarp, pkt, fmd, pkt_src);
        break;

    case VR_ARP_OP_REPLY:
        vr_handle_arp_reply(vrf, &sarp, pkt, fmd);
        break;

    default:
        vr_pfree(pkt, VP_DROP_INVALID_ARP);
    }

    return 1;
}

int
vr_trap(struct vr_packet *pkt, unsigned short trap_vrf,
        unsigned short trap_reason, void *trap_param)
{
    struct vr_interface *vif = pkt->vp_if;
    struct vrouter *router = vif->vif_router;
    struct agent_send_params params;

    if (router->vr_agent_if && router->vr_agent_if->vif_send) {
        params.trap_vrf = trap_vrf;
        params.trap_reason = trap_reason;
        params.trap_param = trap_param;
        return router->vr_agent_if->vif_send(router->vr_agent_if, pkt,
                        &params);
    } else {
        vr_pfree(pkt, VP_DROP_TRAP_NO_IF);
    }

    return 0;
}

static inline bool
vr_my_pkt(unsigned char *pkt_mac, struct vr_interface *vif)
{
    /*
     * Packet is destined to us if:
     * 1) IF destination MAC is our Mac
     * 2) If VIF is service interface
     */
    if (VR_MAC_CMP(pkt_mac, vif->vif_mac) || vif_is_service(vif))
        return true;

    return false;
}

unsigned int
vr_reinject_packet(struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    int handled;
    unsigned short pull_len;
    struct vr_nexthop *nh;
    struct vr_interface *vif = pkt->vp_if;

    vr_printf("%s: from %d in vrf %d to me %d type %d data %d network %d\n",
            __FUNCTION__, pkt->vp_if->vif_idx, fmd->fmd_dvrf,  fmd->fmd_to_me,
            pkt->vp_type, pkt->vp_data, pkt->vp_network_h);

    nh = pkt->vp_nh;
    if (nh) {
        return nh->nh_reach_nh(fmd->fmd_dvrf, pkt, nh, fmd);
    }

    if (fmd->fmd_to_me) {
        handled = vr_l3_input(fmd->fmd_dvrf, pkt, fmd);
        if (handled)
            return 0;
    }

    if (vif_is_virtual(vif)) {
        pull_len = pkt_get_network_header_off(pkt) - pkt_head_space(pkt);
        if (pkt_push(pkt, pull_len)) {
            handled = vr_l2_input(fmd->fmd_dvrf, pkt, fmd);
            if (handled)
                return 0;
        }
    } else {
        if (fmd->fmd_label)
            return vr_bridge_input(vif->vif_router, fmd->fmd_dvrf, pkt, fmd);
    }

    vif_drop_pkt(vif, pkt, 1);

    return 0;
}

/*
 * vr_interface_input() is invoked if a packet ingresses an interface.
 * This function demultiplexes the packet to right input
 * function depending on the protocols enabled on the VIF
 */
unsigned int
vr_virtual_input(unsigned short vrf, struct vr_interface *vif,
                       struct vr_packet *pkt, unsigned short vlan_id)
{
    struct vr_forwarding_md fmd;

    vr_init_forwarding_md(&fmd);
    fmd.fmd_vlan = vlan_id;
    fmd.fmd_dvrf = vrf;

    if (vif->vif_flags & VIF_FLAG_MIRROR_RX) {
        fmd.fmd_dvrf = vif->vif_vrf;
        vr_mirror(vif->vif_router, vif->vif_mirror_id, pkt, &fmd);
    }

    if (vr_pkt_type(pkt, 0) < 0) {
        vif_drop_pkt(vif, pkt, 1);
        return 0;
    }

    if (!vr_flow_forward(pkt->vp_if->vif_router, vrf, pkt, &fmd))
        return 0;

    vr_bridge_input(vif->vif_router, vrf, pkt, &fmd);
    return 0;

}

unsigned int
vr_fabric_input(struct vr_interface *vif, struct vr_packet *pkt,
                unsigned short vlan_id)
{
    int handled = 0;
    unsigned short pull_len;
    struct vr_forwarding_md fmd;

    if (vr_pkt_type(pkt, 0) < 0) {
        vif_drop_pkt(vif, pkt, 1);
        return 0;
    }

    if (pkt->vp_type == VP_TYPE_IP6)
        return vif_xconnect(vif, pkt);

    pull_len = pkt_get_network_header_off(pkt) - pkt_head_space(pkt);

    vr_init_forwarding_md(&fmd);
    fmd.fmd_vlan = vlan_id;
    fmd.fmd_dvrf = vif->vif_vrf;

    pkt_pull(pkt, pull_len);
    if (pkt->vp_type == VP_TYPE_IP || pkt->vp_type == VP_TYPE_IP6)
        handled = vr_l3_input(vif->vif_vrf, pkt, &fmd);
    else if (pkt->vp_type == VP_TYPE_ARP)
        handled = vr_arp_input(vif->vif_vrf, pkt, &fmd, 0);

    if (!handled) {
        pkt_push(pkt, pull_len);
        return vif_xconnect(vif, pkt);
    }

    return 0;
}

int
vr_l2_input(unsigned short vrf, struct vr_packet *pkt,
            struct vr_forwarding_md *fmd)
{
    struct vr_route_req rt;
    struct vr_nexthop *nh;

    rt.rtr_req.rtr_mac_size = VR_ETHER_ALEN;
    rt.rtr_req.rtr_mac =(int8_t *) pkt_data(pkt);
    /* If multicast L2 packet, use broadcast composite nexthop */
    if (IS_MAC_BMCAST(rt.rtr_req.rtr_mac))
        rt.rtr_req.rtr_mac = (int8_t *)vr_bcast_mac;
    rt.rtr_req.rtr_vrf_id = vrf;

    nh = vr_bridge_lookup(vrf, &rt);
    if (!nh) {
        vr_pfree(pkt, VP_DROP_L2_NO_ROUTE);
        return 1;
    }

    /*
     * If there is a label attached to this bridge entry add the
     * label
     */
    if (rt.rtr_req.rtr_label_flags & VR_RT_LABEL_VALID_FLAG)
        fmd->fmd_label = rt.rtr_req.rtr_label;

    nh_output(vrf, pkt, nh, fmd);
    return 1;
}

int
vr_l3_input(unsigned short vrf, struct vr_packet *pkt,
                              struct vr_forwarding_md *fmd)
{
    struct vr_interface *vif = pkt->vp_if;

    if (pkt->vp_type == VP_TYPE_IP) {
        vr_ip_input(vif->vif_router, vrf, pkt, fmd);
        return 1;
    } else if (pkt->vp_type == VP_TYPE_IP6) {
         vr_ip6_input(vif->vif_router, vrf, pkt, fmd);
         return 1;
    }
    return 0;
}

bool
vr_l3_well_known_packet(unsigned short vrf, struct vr_packet *pkt)
{
    unsigned char *data = pkt_data(pkt);
    struct vr_ip *iph;
    struct vr_ip6 *ip6;
    struct vr_udp *udph;
    struct vr_icmp *icmph = NULL;

    if (!(pkt->vp_flags & VP_FLAG_MULTICAST))
        return false;

    if (pkt->vp_type == VP_TYPE_IP) {
        iph = (struct vr_ip *)data;
        if ((iph->ip_proto == VR_IP_PROTO_UDP) &&
                              vr_ip_transport_header_valid(iph)) {
            udph = (struct vr_udp *)(data + iph->ip_hl * 4);
            if (udph->udp_sport == htons(VR_DHCP_SRC_PORT))
                return true;
        }
    } else if (pkt->vp_type == VP_TYPE_IP6) {
        ip6 = (struct vr_ip6 *)data;
        // Bridge link-local traffic
        if (vr_v6_prefix_is_ll(ip6->ip6_dst))
            return false;

        // 0xFF02 is the multicast address used for NDP, DHCPv6 etc
        if (ip6->ip6_dst[0] == 0xFF && ip6->ip6_dst[1] == 0x02) {
            /*
             * Bridge neighbor solicit for link-local addresses
             */
            if (ip6->ip6_nxt == VR_IP_PROTO_ICMP6) {
                icmph = (struct vr_icmp *)((char *)ip6 +
                        sizeof(struct vr_ip6));
            }
            if (icmph && (icmph->icmp_type == VR_ICMP6_TYPE_NEIGH_SOL)
                          && vr_v6_prefix_is_ll(icmph->icmp_data)) {
                return false;
            }
        }
        return true;
    }
    return false;
}

int
vr_trap_l2_well_known_packets(unsigned short vrf, struct vr_packet *pkt,
                              struct vr_forwarding_md *fmd)
{

    if (vif_is_virtual(pkt->vp_if) && well_known_mac(pkt_data(pkt))) {
        vr_trap(pkt, vrf,  AGENT_TRAP_L2_PROTOCOLS, NULL);
        return 1;   
    }

    return 0;
}



/*
 * Function to remove vlan from ethernet header. As it modifies vr_packet
 * structure and not skb, one is expected to invoke vr_pset_data() to
 * modify the data pointer of skb.
 */

int
vr_untag_pkt(struct vr_packet *pkt)
{
    struct vr_eth *eth;
    unsigned char *new_eth;

    eth = (struct vr_eth *)pkt_data(pkt);
    if (eth->eth_proto != htons(VR_ETH_PROTO_VLAN))
        return 0;

    new_eth = pkt_pull(pkt, VR_VLAN_HLEN);
    if (!new_eth)
        return -1;

    memmove(new_eth, eth, (2 * VR_ETHER_ALEN));
    return 0;
}

/*
 * Function to add vlan tag to ethernet header. As it modifies vr_packet
 * structure and not skb, one is expected to invoke vr_pset_data() to
 * modify the data pointer of skb
 */
int
vr_tag_pkt(struct vr_packet *pkt, unsigned short vlan_id)
{
    struct vr_eth *new_eth, *eth;
    unsigned short *vlan_tag;

    eth = (struct vr_eth *)pkt_data(pkt);
    if (eth->eth_proto == htons(VR_ETH_PROTO_VLAN))
        return 0;

    new_eth = (struct vr_eth *)pkt_push(pkt, VR_VLAN_HLEN);
    if (!new_eth)
        return -1;

    memmove(new_eth, eth, (2 * VR_ETHER_ALEN));
    new_eth->eth_proto = htons(VR_ETH_PROTO_VLAN);
    vlan_tag = (unsigned short *)(new_eth + 1);
    *vlan_tag = htons(vlan_id);
    return 0;
}

