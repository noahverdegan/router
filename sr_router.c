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
#include <string.h> /* added for memcpy */
#include <stdlib.h> /* added for malloc */

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

void sendArpReply(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){
  /* Get interface to be src MAC/IP */
  struct sr_if * ifRecord = sr_get_interface(sr, interface);
  sr_ethernet_hdr_t * ethernetHdr = ((sr_ethernet_hdr_t *)packet);
  uint8_t * ethhost = (uint8_t *)(ifRecord->addr);
  uint32_t ethip = ifRecord->ip;

  /* 1. Update Ethernet Header */
  memcpy(ethernetHdr->ether_dhost, ethernetHdr->ether_shost, ETHER_ADDR_LEN * sizeof(uint8_t));
  memcpy(ethernetHdr->ether_shost, ethhost, ETHER_ADDR_LEN * sizeof(uint8_t));

  /* 2. Update Arp Header */
  sr_arp_hdr_t * arpHdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  arpHdr->ar_op = htons(arp_op_reply);
  memcpy(&(arpHdr->ar_tip), &(arpHdr->ar_sip), sizeof(uint32_t));
  memcpy(arpHdr->ar_sha, ethhost, ETHER_ADDR_LEN * sizeof(unsigned char));
  memcpy(arpHdr->ar_tha, ethernetHdr->ether_dhost, ETHER_ADDR_LEN * sizeof(unsigned char));
  memcpy(&(arpHdr->ar_sip), &ethip, sizeof(uint32_t));

  /*printf("---- my ARP reply ----\n");
  print_hdrs(packet, len);*/

  sr_send_packet(sr, packet, len, interface);
}

void sendOutStandingPct(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){
  unsigned char mac[6] = "000000";
  sr_arp_hdr_t * arpHdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if * ifRecord = sr_get_interface(sr, interface);

  /* if (((unsigned long)ntohl(arpHdr->ar_sip)) == 2889876234) return; */
  /* Get packet queue to the destined dst ip */
  struct sr_arpreq * queue = sr_arpcache_insert(&(sr->cache), mac, ntohl(arpHdr->ar_sip));

  if(queue == NULL){
    /* Error Case: Get ARP response, but didn't send ARP request/no queued packet */
    /* printf("NO packet for ip\n");
    print_addr_ip_int(ntohl(arpHdr->ar_sip)); */
    return;
  }

  /* Send all the packets in the queue to the destination */
  struct sr_packet * packetInQueue = queue->packets;
  while(packetInQueue != NULL){
    /* Change dst MAC address */
    memcpy(((sr_ethernet_hdr_t *)(packetInQueue->buf))->ether_dhost, ((sr_ethernet_hdr_t *)packet)->ether_shost, ETHER_ADDR_LEN * sizeof(uint8_t));
    /*printf("---- Forwarded Packet ---- %s\n", ifRecord->name);
    print_hdrs(packetInQueue->buf, len);*/
    sr_send_packet(sr, packetInQueue->buf, packetInQueue->len, ifRecord->name);
    packetInQueue = packetInQueue->next;
  }
  
  /* Free packets */
  sr_arpreq_destroy(&(sr->cache), queue);
}

int checkIPToMe(struct sr_instance* sr, uint32_t ip){
  int targetToMe = 0;
  struct sr_if* interfaces = sr->if_list;

  /* Check if ip is one of the ip of router's interfaces */
  while(interfaces != NULL){
    if(interfaces->ip == ip){
      targetToMe = 1;
    }
    interfaces = interfaces->next;
  }

  return targetToMe;
}

int isIPPacketValid(sr_ip_hdr_t * iphdr){
  uint16_t checksum = iphdr->ip_sum;
  uint16_t zero = 0;

  /* zero out checksum */
  memcpy(&(iphdr->ip_sum), &zero, sizeof(uint16_t));
  
  /* Check version == IPv4, header length, packet length, and the checksum */
  return (iphdr->ip_v == 4) && (iphdr->ip_hl >= 5) 
          && (ntohs(iphdr->ip_len) >= (iphdr->ip_hl)) 
          && (checksum == cksum(iphdr, sizeof(sr_ip_hdr_t)));
}

void sendICMPReply(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){
  /* Pointers to Ethernet, ip, and ICMP header */
  sr_ethernet_hdr_t * ethernetHdr = ((sr_ethernet_hdr_t *)packet);
  sr_ip_hdr_t * ipHdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t11_hdr_t *icmp_hdr = (sr_icmp_t11_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  /* Get outgoing interface */
  struct sr_if * ifRecord = sr_get_interface(sr, interface);
  uint8_t * ethhost = (uint8_t *)(ifRecord->addr);
  uint16_t icmpChecksum = icmp_hdr->icmp_sum;
  uint16_t zero = 0;

  /* Clear checksum field */
  memcpy(&(icmp_hdr->icmp_sum), &zero, sizeof(uint16_t));

  /* Only reply to ICMP echo request (type 8) */
  if(icmp_hdr->icmp_type != 8 || (icmpChecksum != cksum(icmp_hdr, (ntohs(ipHdr->ip_len) - sizeof(sr_ip_hdr_t))))) return;

  /* 1. Update Ethernet Header */
  memcpy(ethernetHdr->ether_dhost, ethernetHdr->ether_shost, ETHER_ADDR_LEN * sizeof(uint8_t));
  memcpy(ethernetHdr->ether_shost, ethhost, ETHER_ADDR_LEN * sizeof(uint8_t));

  /* 2. Update IP Header */
  uint32_t org_dst = ipHdr->ip_dst;
  memcpy(&(ipHdr->ip_dst), &(ipHdr->ip_src), sizeof(uint32_t));
  memcpy(&(ipHdr->ip_src), &org_dst, sizeof(uint32_t));
  uint16_t checksum = cksum(ipHdr, sizeof(sr_ip_hdr_t)); 
  memcpy(&(ipHdr->ip_sum), &checksum, sizeof(uint16_t));

  /* 3. Update ICMP Header */
  uint8_t icmpReplyType = 0;
  memcpy(&(icmp_hdr->icmp_type), &icmpReplyType, sizeof(uint8_t));
  checksum = cksum(icmp_hdr, (ntohs(ipHdr->ip_len) - sizeof(sr_ip_hdr_t))); 
  memcpy(&(icmp_hdr->icmp_sum), &checksum, sizeof(uint16_t));

  /*printf("---- my ICMP reply ----\n");
  print_hdrs(packet, len);*/

  /* Send ICMP echo reply  */
  sr_send_packet(sr, packet, len, interface);
}

void ipError(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, uint8_t icmpType, uint8_t code){
  /* Pointers to Ethernet, ip, and ICMP header */
  sr_ethernet_hdr_t * ethernetHdr = ((sr_ethernet_hdr_t *)packet);
  sr_ip_hdr_t * ipHdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t11_hdr_t *icmp_hdr = (sr_icmp_t11_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  
  /* Get outgoing interface */
  struct sr_if * ifRecord = sr_get_interface(sr, interface);
  uint8_t * ethhost = (uint8_t *)(ifRecord->addr);
  uint32_t ethip = ifRecord->ip;

  /* 1. Update Ethernet Header */
  if(code == 0) memcpy(ethernetHdr->ether_dhost, ethernetHdr->ether_shost, ETHER_ADDR_LEN * sizeof(uint8_t));
  memcpy(ethernetHdr->ether_shost, ethhost, ETHER_ADDR_LEN * sizeof(uint8_t));
  memcpy(icmp_hdr->data, ipHdr, sizeof(sr_ip_hdr_t) + 8);

  /* 2. Update IP Header */
  memcpy(&(ipHdr->ip_dst), &(ipHdr->ip_src), sizeof(uint32_t));
  memcpy(&(ipHdr->ip_src), &ethip, sizeof(uint32_t));
  ipHdr->ip_sum = 0;
  ipHdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
  uint16_t checksum = cksum(ipHdr, sizeof(sr_ip_hdr_t)); 
  memcpy(&(ipHdr->ip_sum), &checksum, sizeof(uint16_t));
  
  /* 3. Update ICMP Header */
  /* ICMP Type: 11 (Code 0 - time exceeded), 3 (Code 0 - net unreachable, 1 - host unreachable)*/
  if(code != 0) code = 1;
  uint16_t zero = 0;
  memcpy(&(icmp_hdr->icmp_sum), &zero, sizeof(uint16_t));
  memcpy(&(icmp_hdr->icmp_type), &icmpType, sizeof(uint8_t));
  memcpy(&(icmp_hdr->icmp_code), &code, sizeof(uint8_t));
  uint16_t icmpchecksum = cksum(icmp_hdr, sizeof(sr_icmp_t11_hdr_t));
  memcpy(&(icmp_hdr->icmp_sum), &icmpchecksum, sizeof(uint16_t));

  /*printf("---- my Time Exceeded(11)/noMatch(3.0)---- %d\n", len);
  print_hdrs(packet, len);*/

  /* Send Time Exceeded */
  sr_send_packet(sr, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t), interface);
}

struct sr_rt* matchRoutingTable(struct sr_instance* sr, uint32_t dstAddr){
  struct sr_rt* rtEntry = sr->routing_table;

  /* Find an entry with dst addr == dstAddr */
  while(rtEntry != NULL){
    if(rtEntry->dest.s_addr == dstAddr) 
      return rtEntry;
    rtEntry = rtEntry->next;
  }
  
  return NULL;
}

void sendARPRequest(struct sr_instance* sr, uint32_t dstip){
  /* Allocate memory for ARP request */
  uint8_t * packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
  sr_ethernet_hdr_t * ethernetHdr = ((sr_ethernet_hdr_t *)packet);
  
  /* Get interface MAC/ip */
  char * sendingInterface = matchRoutingTable(sr, htonl(dstip))->interface; 
  struct sr_if * ifRecord = sr_get_interface(sr, sendingInterface);
  uint8_t * ethhost = (uint8_t *)(ifRecord->addr);
  uint32_t ethip = ifRecord->ip;

  /* 1. Construct Ethernet Header: src, dst(broadcast), type: arp */
  int index = 0;
  for(index = 0; index < ETHER_ADDR_LEN; index++){
    ethernetHdr->ether_dhost[index] = 255;
  }
  ethernetHdr->ether_type = htons(ethertype_arp);
  memcpy(ethernetHdr->ether_shost, ethhost, ETHER_ADDR_LEN * sizeof(uint8_t)); 

  /* 2. Construct Arp Header */
  sr_arp_hdr_t * arpHdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  arpHdr->ar_hrd = htons(1);
  arpHdr->ar_pro = htons(2048);
  arpHdr->ar_hln = 6;
  arpHdr->ar_pln = 4;
  arpHdr->ar_op = htons(arp_op_request);
  arpHdr->ar_tip = htonl(dstip);
  memcpy(arpHdr->ar_sha, ethhost, ETHER_ADDR_LEN * sizeof(unsigned char));
  arpHdr->ar_sip = ethip;
  for(index = 0; index < ETHER_ADDR_LEN; index++){
    arpHdr->ar_tha[index] = 0;
  }

  /* printf("---- my ARP Request ----\n");
  print_hdrs(packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)); */

  /* Send ARP request */
  sr_send_packet(sr, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), sendingInterface);
  free(packet); /* Check later */ 
}

void queuePacket(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, struct sr_rt* rtEntry){
  sr_ethernet_hdr_t * ethernetHdr = ((sr_ethernet_hdr_t *)packet);
  sr_ip_hdr_t * ipHdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  
  /* Outgoing Interface */
  struct sr_if * ifRecord = sr_get_interface(sr, rtEntry->interface);
  uint8_t * ethhost = (uint8_t *)(ifRecord->addr);
  
  /* TTL -1, compute checksum */
  ipHdr->ip_ttl = ipHdr->ip_ttl - 1;
  memcpy(ethernetHdr->ether_dhost, ethernetHdr->ether_shost, ETHER_ADDR_LEN * sizeof(uint8_t)); 
  memcpy(ethernetHdr->ether_shost, ethhost, ETHER_ADDR_LEN * sizeof(uint8_t));
  uint16_t checksum = cksum(ipHdr, sizeof(sr_ip_hdr_t)); 
  memcpy(&(ipHdr->ip_sum), &checksum, sizeof(uint16_t));

  /*printf("queue packet for ip:\n");
  print_addr_ip_int(ntohl(ipHdr->ip_dst));
  print_hdrs(packet, len);*/

  /* Queue Packet */
  struct sr_arpreq * queue = sr_arpcache_queuereq(&(sr->cache), ntohl(ipHdr->ip_dst), packet, len, interface);

  /* Send first ARP Request */
  /* printf("incrementing...\n"); */
  if(queue->times_sent == 0){
    queue->times_sent ++;
    sendARPRequest(sr, ntohl(ipHdr->ip_dst));
  }
}

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
  /* print_hdrs(packet, len); */

  /* Ethernet sanity check */
  if(len < sizeof(sr_ethernet_hdr_t)) return;

  uint8_t * networklayerPacket = packet + sizeof(sr_ethernet_hdr_t);

  if(ethertype(packet) == ethertype_arp){
    /* ARP sanity check */
    if(len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) return;
    if(!checkIPToMe(sr, ((sr_arp_hdr_t *)networklayerPacket)->ar_tip)) return;

    if(ntohs(((sr_arp_hdr_t *)networklayerPacket)->ar_op) == arp_op_request){
      /* 1. Request to Me -> Construct ARP reply */
      sendArpReply(sr, packet, len, interface);
    }else if(ntohs(((sr_arp_hdr_t *)networklayerPacket)->ar_op) == arp_op_reply){
      /* 2. Reply to Me */
      sendOutStandingPct(sr, packet, len, interface);
    }
  }
  else if(ethertype(packet) == ethertype_ip){
    /* IP packet sanity check */
    if(!isIPPacketValid((sr_ip_hdr_t *)networklayerPacket)) return;

    if(checkIPToMe(sr, ((sr_ip_hdr_t *)networklayerPacket)->ip_dst)){
      /* 1. Directed to Me */
      if(((sr_ip_hdr_t *)networklayerPacket)->ip_p == ip_protocol_icmp){
        /* ICMP packet */
        sendICMPReply(sr, packet, len, interface);
      }
    }else{
      /* 2. Not Directed to Me */
      if(((sr_ip_hdr_t *)networklayerPacket)->ip_ttl <= 1){
        /* Send Time Exceeded */
        ipError(sr, packet, len, interface, 11, 0);
      }
      else{
        struct sr_rt* rtEntry = matchRoutingTable(sr, ((sr_ip_hdr_t *)networklayerPacket)->ip_dst);
        if(rtEntry != NULL){
          /* Match in Routing Table */
          queuePacket(sr, packet, len, interface, rtEntry);
        }else{
          /* No Match in Routing Table */
          ipError(sr, packet, len, interface, 3, 0);
        }
      }
    }
  }

}/* end sr_ForwardPacket */

