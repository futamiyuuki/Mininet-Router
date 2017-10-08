/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);

    /* fill in code here */
    if(len < sizeof(sr_ethernet_hdr_t)) {
        fprintf(stderr, "length not long enough\n");
        return;
    }

    /* receiving raw ethernet frame, identying arp/ip and handle them */
    if(ethertype(packet) == ethertype_arp) {
        fprintf(stderr, "received ARP Packet\n");
        handleARP(sr, packet, len, interface);
    } else if(ethertype(packet) == ethertype_ip) {
        fprintf(stderr,"received IP Packet\n");
        handleIP(sr, packet, len, interface);
    } else {
        fprintf(stderr,"received Packet other than ARP or IP\n");
    }

}/* end sr_ForwardPacket */

void handleARP(struct sr_instance* sr,
               uint8_t* packet,
               unsigned int len,
               char* interface)
{
    /* check length of packet */
    if(len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
        fprintf(stderr,"ARP Packet not long enough\n");
        return;
    }

    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*) (packet + 
                            sizeof(sr_ethernet_hdr_t)); /* arp header */
    struct sr_if* p_if = sr_get_interface(sr,interface); /* packet interface */

    if(ntohs(arp_hdr->ar_op) == arp_op_request) {
        /* resquested, needs to create ARP reply and send it back */
        fprintf(stderr,"processing ARP Request\n");

        /* check if interface ip and header target ip different */
        if(p_if->ip != arp_hdr->ar_tip) {
            fprintf(stderr,"Packet and Router does not match\n");
            return;
        }

        /* creates the reply packet to the request */
        uint8_t* reply_packet;
        size_t allosize = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
        reply_packet = malloc(allosize);
        memset(reply_packet, 0, sizeof(uint8_t) * len);

        /* setup ethernet header */
        sr_ethernet_hdr_t* eth_part = (sr_ethernet_hdr_t*) reply_packet;
        eth_part->ether_type = htons(ethertype_arp);
        sr_ethernet_hdr_t* temp_eth = (sr_ethernet_hdr_t*) packet;
        memcpy(eth_part->ether_dhost, temp_eth->ether_shost, ETHER_ADDR_LEN);
        memcpy(eth_part->ether_shost, p_if->addr, ETHER_ADDR_LEN);

        /* setup arp header (after eth header) */
        sr_arp_hdr_t* arp_part = (sr_arp_hdr_t*) (reply_packet +
                                 sizeof(sr_ethernet_hdr_t));
        arp_part->ar_hrd = htons(arp_hrd_ethernet);
        arp_part->ar_pro = htons(ethertype_ip);
        arp_part->ar_hln = ETHER_ADDR_LEN;
        arp_part->ar_pln = sizeof(uint32_t);
        arp_part->ar_op = htons(arp_op_reply);
        arp_part->ar_sip = p_if->ip;
        memcpy(arp_part->ar_sha, p_if->addr, ETHER_ADDR_LEN);
        arp_part->ar_tip = arp_hdr->ar_sip;
        memcpy(arp_part->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);

        /* send the reply packet then free the memory */
        sr_send_packet(sr, reply_packet, allosize, p_if->name);
        /* free(reply_packet); */
    } else if(ntohs(arp_hdr->ar_op) == arp_op_reply) {
        /* send all waiting packets */
        fprintf(stderr,"processing ARP Reply\n");
        struct sr_arpreq* arp_req = sr_arpcache_insert(&sr->cache,
                                    arp_hdr->ar_sha, arp_hdr->ar_sip);

        if(arp_req != NULL) {
            struct sr_packet* curr_packet = arp_req->packets;
            while(curr_packet != NULL) {
                /* creates packet to be forwarded */
                size_t allosize = curr_packet->len;
                uint8_t* packet_2send;
                packet_2send = malloc(allosize);
                memcpy(packet_2send,curr_packet->buf,allosize);
                /* interface */
                struct sr_if* cp_if;
                cp_if = sr_get_interface(sr, curr_packet->iface);

                /* setup ethernet header */
                sr_ethernet_hdr_t* eth_part = (sr_ethernet_hdr_t*)packet_2send;
                eth_part->ether_type = htons(ethertype_ip);
                memcpy(eth_part->ether_shost, cp_if->addr, ETHER_ADDR_LEN);
                memcpy(eth_part->ether_dhost,arp_hdr->ar_sha,ETHER_ADDR_LEN);

                /* setup ip header  */
                sr_ip_hdr_t* buf_ip = (sr_ip_hdr_t*) (packet_2send + 
                                      sizeof(sr_ethernet_hdr_t));
                buf_ip->ip_sum = 0;
                buf_ip->ip_sum = cksum(buf_ip,sizeof(sr_ip_hdr_t));

                /* send packet and iterate to next packet */
                /*struct sr_packet* packet_sent = packet_2send; */
                sr_send_packet(sr, packet_2send, allosize, cp_if->name);
                curr_packet = curr_packet->next;
                /* free(packet_sent); */
            }
            /* remove arp request entry from queue after sending  */
            sr_arpreq_destroy(&sr->cache, arp_req);
        } else {
            fprintf(stderr,"IP not found in request queue\n");
        }
    } else {
        fprintf(stderr,"ar_op error\n");
    }
}

void handleIP(struct sr_instance* sr,
              uint8_t* packet,
              unsigned int len,
              char* interface)
{
    /* check length of packet */
    if(len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        fprintf(stderr,"IP Packet not long enough\n");
        return;
    }

    /* IP Header and Interface from router in the packet */
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    struct sr_if* p_if = sr_get_interface(sr, interface);

    /* validate IP header (should not be IPv6, check ip_hl, check ip_len) */
    if(ip_hdr->ip_v == 6) {
        fprintf(stderr,"Should not use IPv6\n");
        return;
    }
    if(ip_hdr->ip_hl < 5 || ip_hdr->ip_len > IP_MAXPACKET) {
        fprintf(stderr,"IP header size / total size not accurate");
        return;
    }

    /* validate IP checksum */
    uint16_t temp_cksum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    if(cksum(ip_hdr,sizeof(sr_ip_hdr_t)) != temp_cksum) {
        fprintf(stderr,"IP checksum not same after recalculation\n");
        return;
    }

    /* check if packet is for me */
    struct sr_if* curr_if = sr->if_list;
    while(curr_if) {
        if(ip_hdr->ip_dst == curr_if->ip) {
            /* when packet is for current router */
            fprintf(stderr,"Packet for current router\n");

            /* check if udp/tcp or ping */
            if(ip_hdr->ip_p == ip_protocol_icmp) {
                fprintf(stderr,"ICMP echo request, generate echo reply");

                /* check if icmp (type 0) is valid */
                if(len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +
                         sizeof(sr_icmp_hdr_t)) {
                    fprintf(stderr,"len not long enough for icmp header");
                    return;
                }

                /* send packet of type 0 code 0 (echo reply) */
                send_ICMP(sr,packet,len,interface,0x00,0x00,curr_if->ip,
                          ip_hdr->ip_src);

            } else if(ip_hdr->ip_p == 6 || ip_hdr->ip_p == 17) {
                fprintf(stderr,"tcp or udp, generate port unreachable");

                /* validate length */
                /*if(len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +
                         sizeof(sr_icmp_t3_hdr_t)) {
                    fprintf(stderr,"len not long enough for icmp header");
                    return;
                }*/

                /* send ICMP type 3 code 3 */
                send_ICMP(sr, packet, len, interface, 0x03, 0x03, curr_if->ip,
                          ip_hdr->ip_src);
            } else {
                fprintf(stderr,"PROTOCOL unidentified!!!\n");
            }
            return;
        }
        curr_if = curr_if->next;
    }

    /* when packet is not for current router */
    fprintf(stderr,"Packet is not for current router\n");
    if(ip_hdr->ip_ttl <= 1) {
        /* packet dead, send ICMP time exceeded (type 11 code 0) */
        fprintf(stderr,"ICMP time exceeded");
        send_ICMP(sr,packet,len,interface,0x0b,0x00,p_if->ip,ip_hdr->ip_src);
        return;
    } else {
        /* packet alive */
        /* checking lpm */
        struct sr_rt* lpm = longestPrefixMatch(sr->routing_table, 
            ip_hdr->ip_dst);
        if(lpm == NULL) {
            /* no longest match */
            fprintf(stderr,"longest prefix does not exist\n");
            send_ICMP(sr,packet,len,interface,0x03,0x00,p_if->ip,ip_hdr->ip_src);
            return;
        }

        /* decrement ttl and recalc checksum */
        ip_hdr->ip_ttl--;
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr,sizeof(sr_ip_hdr_t));

        char* lpm_if = lpm->interface; /* outoing interface */
        struct sr_if* lpm_p_if = sr_get_interface(sr, lpm_if);

        /* lookup rt_table to check if there's an entry */
        struct sr_arpentry* arp_entry = 
            sr_arpcache_lookup(&sr->cache,lpm->gw.s_addr);

        if(arp_entry == NULL) {
            /* arp not in cache, enque */
            fprintf(stderr, "arp entry not found in cache\n");

            struct sr_arpreq* arp_req = sr_arpcache_queuereq(&sr->cache,
                ip_hdr->ip_dst, packet, len, lpm_if);

            /* since we can't find the entry, we just handle_arpreq */
            handle_arpreq(sr,arp_req);
        } else {
            /* in cache, forward */
            fprintf(stderr,"entry exists in cache, forward\n");

            /* change info in packet and forward */
            /* setup ethernet part */
            sr_ethernet_hdr_t* eth_fwd = (sr_ethernet_hdr_t*) packet;
            memcpy(eth_fwd->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
            memcpy(eth_fwd->ether_shost, lpm_p_if->addr, ETHER_ADDR_LEN);

            /* setup ip part */
            sr_ip_hdr_t* ip_fwd = (sr_ip_hdr_t*) (packet +
                                  sizeof(sr_ethernet_hdr_t));
            ip_fwd->ip_sum = 0;
            ip_fwd->ip_sum = cksum(ip_fwd, sizeof(sr_ip_hdr_t));
            sr_send_packet(sr, packet, len, lpm_if);

            free(arp_entry);
        }
    }
}

void send_ICMP(struct sr_instance* sr, uint8_t* packet, unsigned int len,
               char* interface, uint8_t type, uint8_t code, uint32_t ip_src, 
               uint32_t ip_dst) {

    struct sr_if* p_if = sr_get_interface(sr, interface);

    size_t allosize;
    if(type == 0x00) {
        allosize = len;
    } else {
        allosize = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +
                   sizeof(sr_icmp_t3_hdr_t);
    }
    uint8_t* packet2send = malloc(allosize);
    memset(packet2send, 0, allosize);
    if(type == 0x00) {
        memcpy(packet2send,packet,allosize);
    }

    /* setup Ethernet header */
    sr_ethernet_hdr_t* eth_part = (sr_ethernet_hdr_t*) packet2send;
    sr_ethernet_hdr_t* temp_eth_part = (sr_ethernet_hdr_t*) packet;
    eth_part->ether_type = htons(ethertype_ip);
    memcpy(eth_part->ether_shost, p_if->addr, ETHER_ADDR_LEN);
    memcpy(eth_part->ether_dhost, temp_eth_part->ether_shost, ETHER_ADDR_LEN);

    /* setup IP header */
    sr_ip_hdr_t* ip_part=(sr_ip_hdr_t*)(packet2send+sizeof(sr_ethernet_hdr_t));
    sr_ip_hdr_t* temp_ip=(sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    memcpy(ip_part,temp_ip,sizeof(sr_ip_hdr_t));
    ip_part->ip_src = ip_src;
    ip_part->ip_dst = ip_dst;
    if(type != 0x00) {
        ip_part->ip_hl = 5; /* icmpt3 size divided by 4(bytes) */
        ip_part->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        ip_part->ip_p = ip_protocol_icmp;
        /*ip_part->ip_ttl = 64;*/ /* saw the number 64 on piazza lol */
        ip_part->ip_ttl = INIT_TTL;
    }
    ip_part->ip_sum = 0;
    ip_part->ip_sum = cksum(ip_part,sizeof(sr_ip_hdr_t));

    /* setup ICMP type 0 or 3 or 11 header */
    if(type == 0x00) {
        sr_icmp_hdr_t* icmp_part= (sr_icmp_hdr_t*) (packet2send +
            sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        icmp_part->icmp_type = type; /* echo reply type */
        icmp_part->icmp_code = type; /* echo reply code */
        uint16_t icmpl = ntohs(temp_ip->ip_len) - sizeof(sr_ip_hdr_t);
        /*uint16_t temp_icmp_cksum = icmp_part->icmp_sum;*/
        icmp_part->icmp_sum = 0;
        icmp_part->icmp_sum = cksum(icmp_part, icmpl);
    } else if(type == 0x0b) {
        fprintf(stderr,"sending type 11\n");
        sr_icmp_t11_hdr_t* icmp_part = (sr_icmp_t11_hdr_t*) (packet2send +
            sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        /* sr_ip_hdr_t* temp_ip=(sr_ip_hdr_t*)(packet2send + 
            sizeof(sr_ethernet_hdr_t)); */
        memcpy(icmp_part->data, temp_ip,ICMP_DATA_SIZE);
        icmp_part->icmp_type = type;
        icmp_part->icmp_code = code;
        icmp_part->icmp_sum = 0;
        icmp_part->icmp_sum = cksum(icmp_part, sizeof(sr_icmp_t11_hdr_t));
    } else {
        fprintf(stderr, "sending type 3\n");
        sr_icmp_t3_hdr_t* icmp_part = (sr_icmp_t3_hdr_t*) (packet2send +
            sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        /*sr_ip_hdr_t* temp_ip=(sr_ip_hdr_t*)(packet2send+
            sizeof(sr_ethernet_hdr_t));*/
        memcpy(icmp_part->data, temp_ip,ICMP_DATA_SIZE);
        icmp_part->icmp_type = type;
        icmp_part->icmp_code = code;
        icmp_part->icmp_sum = 0;
        icmp_part->icmp_sum = cksum(icmp_part, sizeof(sr_icmp_t3_hdr_t));
    }
    
    sr_send_packet(sr, packet2send, allosize, p_if->name);
    /* free(packet2send); */
}

struct sr_rt* longestPrefixMatch(struct sr_rt* routable, uint32_t ip_dst) {
    struct sr_rt* match = NULL;
    unsigned long match_len = 0;

    /* check if prefix match, and keep updating lpm when there's longer match*/
    while(routable != NULL) {
        if(match_len <= routable->mask.s_addr) {
            /* masked result needs to be the same */
            if((routable->dest.s_addr & routable->mask.s_addr) ==
               (ip_dst & routable->mask.s_addr)) {
                match = routable;
                match_len = routable->mask.s_addr;
            }
        }

        routable = routable->next;
    }

    return match;
}

