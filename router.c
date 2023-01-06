#include <queue.h>
#include "skel.h"

//rtable entry
struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
};

//arp entry
struct arp_entry {
	__u32 ip;
	uint8_t mac[6];
};

//rtable declaration
struct route_table_entry *rtable;
int rtable_size;

//arp_table declaration
struct arp_entry *arp_table;
int arp_table_len;

int read_rtable(FILE *inputfile)
{
	int aux = 1000;
	int i=0;
	char prefix[50];
	char next_hop[50];
	char mask[50];
	char interface[50];
	while(fscanf(inputfile,"%s %s %s %s", prefix, next_hop, mask, interface) != EOF)
	{
		rtable[i].prefix = inet_addr(prefix);
		rtable[i].next_hop = inet_addr(next_hop);
		rtable[i].mask = inet_addr(mask);
		rtable[i].interface = atoi(interface);
		i++;
		if(i >= aux)
			{
				aux += 1000;
				rtable = realloc(rtable,  sizeof(struct route_table_entry) * aux);
			}
	}
	return i;
}

struct route_table_entry *get_best_route(__u32 dest_ip) {
	struct route_table_entry *max = NULL;
	for(int i = 0; i < rtable_size; i++)
	{
		if((rtable[i].mask & dest_ip) ==  rtable[i].prefix)
		{
			if(max == NULL)
				max = &rtable[i];
			else if(rtable[i].mask > max->mask)
				max = &rtable[i];
		}
	}
	return max;
}

struct arp_entry *get_arp_entry(__u32 ip) {
	for(int i = 0; i < arp_table_len; i++)
	{
		if(arp_table[i].ip == ip)
			return &arp_table[i];
	}
    return NULL;
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;
	init(argc - 2, argv + 2);
	FILE *input_file = fopen(argv[1],"r");
	rtable = malloc(sizeof(struct route_table_entry) * 1000);
	rtable_size = read_rtable(input_file);
	int arp_alloc = 1;
	arp_table = malloc(sizeof(struct  arp_entry) * arp_alloc);
	queue pkt_queue;
	pkt_queue = queue_create();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		struct ether_header* eth_hdr = (struct ether_header *)m.payload;
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));

		//checking if it is an ip packet
		if(eth_hdr->ether_type == htons(ETHERTYPE_IP))
		{
			//if it is for the router
			if(inet_addr(get_interface_ip(m.interface)) == ip_hdr->daddr)
		 	{
				struct icmphdr* icmp_hdr = parse_icmp(m.payload);
				if(icmp_hdr != NULL && icmp_hdr->type == 8) //an echo request
				{
					//we send an icmp reply
					send_icmp(ip_hdr->saddr,ip_hdr->daddr,eth_hdr->ether_dhost,eth_hdr->ether_shost,0,0,m.interface,icmp_hdr->un.echo.id,icmp_hdr->un.echo.sequence);
					continue;
				}
			}

			struct route_table_entry *best_entry = get_best_route(ip_hdr->daddr);
			if(best_entry == NULL)
			{
				//host unreacheable
				send_icmp_error(ip_hdr->saddr,ip_hdr->daddr,eth_hdr->ether_dhost,eth_hdr->ether_shost,3,0,m.interface);
				continue;
			}
			//wrong checksum
			if(ip_checksum(ip_hdr,sizeof(struct iphdr))!=0)
				continue;
			if(ip_hdr->ttl <= 1) 
			{
				//time exceeded
				send_icmp_error(ip_hdr->saddr,ip_hdr->daddr,eth_hdr->ether_dhost,eth_hdr->ether_shost,11,0,m.interface);
				continue;
			}
			ip_hdr->ttl --;
			ip_hdr->check = 0;
			ip_hdr->check = ip_checksum(ip_hdr,sizeof(struct iphdr));
			struct arp_entry *entry = get_arp_entry(ip_hdr->daddr);
			//if we don't know the mac address we seend an arp request
			if(entry == NULL)
			{
				packet queued_pkt;
				memcpy(&queued_pkt,&m,sizeof(packet));
				queue_enq(pkt_queue,&queued_pkt);
				struct ether_header new_ether;
				get_interface_mac(best_entry->interface, new_ether.ether_shost);
				for(int i = 0; i < ETH_ALEN; i++)
					new_ether.ether_dhost[i] = 255;
				new_ether.ether_type = htons(ETHERTYPE_ARP);
				send_arp(best_entry->next_hop, inet_addr(get_interface_ip(best_entry->interface)), &new_ether, best_entry->interface, htons(ARPOP_REQUEST));
				continue;
			}
			//we have the mac address
			memcpy(eth_hdr->ether_dhost,entry->mac,ETH_ALEN);
			get_interface_mac(best_entry->interface,eth_hdr->ether_shost);
			send_packet(best_entry->interface,&m);
			continue;
		}
		//if we have an arp packet
		if(eth_hdr->ether_type == htons(ETHERTYPE_ARP))
		{
	    struct arp_header* arp_hdr = parse_arp(m.payload);
		//we get an arp request for the router
		if(arp_hdr != NULL && ntohs(arp_hdr->op) == ARPOP_REQUEST && inet_addr(get_interface_ip(m.interface)) == arp_hdr->tpa)
		{
			struct ether_header new_ether;
			build_ethhdr(&new_ether, eth_hdr->ether_dhost, eth_hdr->ether_shost, htons(ETHERTYPE_ARP));
			get_interface_mac(m.interface, new_ether.ether_shost);
			//we send an arp reply
			send_arp(arp_hdr->spa, arp_hdr->tpa, &new_ether, m.interface, htons(ARPOP_REPLY));
			continue;
		}
		//we get an arp reply
		if(arp_hdr != NULL && ntohs(arp_hdr->op) ==  ARPOP_REPLY)
		{
			//we update the arp table
			if(get_arp_entry(arp_hdr->spa) == NULL)
			{
				memcpy(arp_table[arp_table_len].mac, arp_hdr->sha, ETH_ALEN);
				arp_table[arp_table_len].ip = arp_hdr->spa;
				arp_table_len++;
				if(arp_table_len >= arp_alloc)
				{
					arp_alloc++;
					arp_table = realloc(arp_table, sizeof(struct  arp_entry) * arp_alloc);
				}
			}
			//queue to store packets to be transmitted
			queue new_pkt_queue = queue_create(); 
			while(!queue_empty(pkt_queue))
			{
				packet* pkt = (packet*) queue_deq(pkt_queue);
				struct ether_header* ether_hdr = (struct ether_header *)pkt->payload;
				struct iphdr *pkt_ip_hdr = (struct iphdr *)(pkt->payload + sizeof(struct ether_header));
				struct route_table_entry* best_route = get_best_route(pkt_ip_hdr->daddr);
				if(best_route->next_hop != arp_hdr->spa)
					queue_enq(new_pkt_queue,pkt);
				else
				{
					memcpy(ether_hdr->ether_dhost,arp_hdr->sha,ETH_ALEN);
					get_interface_mac(best_route->interface,ether_hdr->ether_shost);
		            send_packet(best_route->interface, pkt);
				}
			}
			//we put the remaining untransmitted packets back into the queue
			while (!queue_empty(new_pkt_queue))
				queue_enq(pkt_queue, (packet*) queue_deq(new_pkt_queue));
			continue;
		}
		}
	}
}
