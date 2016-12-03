/**********************************************************************
* file:   testtask_se.c
* Author: Bohdan Zhyvko
*
* Description: 
*
* Compile with:
* gcc testtask_se.c -lpcap 
*
* Usage:
* a.out (# of packets) "filter string" interface macaddress
*
* a.out 50 "dst port 80 and ether src 00:0C:29:E8:54:46" eth0 00:0C:29:E8:54:46
*
*
**********************************************************************/

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <unistd.h>

unsigned char* mac = NULL;
int tcp_count = 0, udp_count = 0, mac_scount = 0, mac_dcount = 0;

u_int16_t handle_ethernet
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);

/* looking at ethernet headers */

void packet_parser
	(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
	struct ip* iphdr;
	struct tcphdr* tcphdr;
	struct udphdr* udphdr;
	struct ether_header* eptr;

	unsigned char* mac_dst = NULL;
	unsigned char* mac_src = NULL;

	eptr = (struct ether_header *) packet;
	iphdr = (struct ip*)(packet+14);

	char srcip[256], dstip[256];
	
	/* get source and destination MAC addresses from packet */
	mac_src = ((unsigned char *) &eptr->ether_shost);
	mac_dst = ((unsigned char *) &eptr->ether_dhost);
 
	printf("Mac : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X" , mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5]);
	printf(" : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n" , mac_dst[0], mac_dst[1], mac_dst[2], mac_dst[3], mac_dst[4], mac_dst[5]);
	
	/* compare with specified MAC address in argv[4] */
	if(mac[0] == mac_dst[0] && mac[1] == mac_dst[1] && mac[2] == mac_dst[2] && mac[3] == mac_dst[3] && mac[4] == mac_dst[4] && mac[5] == mac_dst[5])
		{ mac_dcount++; }
	if(mac[0] == mac_src[0] && mac[1] == mac_src[1] && mac[2] == mac_src[2] && mac[3] == mac_src[3] && mac[4] == mac_src[4] && mac[5] == mac_src[5])
		{ mac_scount++; }
	
	/* if packet is IP check print src/dst ip addresses and count TCP / UDP */
	if(ntohs (eptr->ether_type) == ETHERTYPE_IP)
	{
		strcpy(srcip, inet_ntoa(iphdr->ip_src));
		strcpy(dstip, inet_ntoa(iphdr->ip_dst));

		if(iphdr->ip_p == IPPROTO_TCP)
		{
			tcphdr = (struct tcphdr*)pkthdr;
	        printf("TCP  %s:%d -> %s:%d\n", srcip, ntohs(tcphdr->source), dstip, ntohs(tcphdr->dest));
			tcp_count ++ ; 
		}
		if(iphdr->ip_p == IPPROTO_UDP)
		{
			udphdr = (struct udphdr*)pkthdr;
			printf("UDP  %s:%d -> %s:%d\n", srcip, ntohs(udphdr->source), dstip, ntohs(udphdr->dest));
			udp_count ++ ; 
		}
	}
}

u_int16_t handle_ethernet (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    struct ether_header *eptr;  /* net/ethernet.h */

    /* lets start with the ether header... */
    eptr = (struct ether_header *) packet;
    return eptr->ether_type;
}

int main(int argc,char **argv)
{ 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    struct bpf_program fp;      /* hold compiled program     */
    bpf_u_int32 maskp;          /* subnet mask               */
    bpf_u_int32 netp;           /* ip                        */
    u_char* args = NULL;
    struct  ether_addr* in_mac_addr;

    /* Filter options must be passed in as a string */
    if(argc < 5){ 
        fprintf(stdout,"Usage: %s numpackets \"options\" interface macaddress \n", argv[0]);
        return 0;
    }

    /* ask pcap for the network address and mask of the device */
    pcap_lookupnet(argv[3],&netp,&maskp,errbuf);

    /* open device for reading. NOTE: defaulting to
     * promiscuous mode*/
    descr = pcap_open_live(argv[3],BUFSIZ,1,-1,errbuf);  

    if(descr == NULL)
    { printf("pcap_open_live(): %s\n",errbuf); exit(1); }

	/* Convert specified MAC address to numeric and set uchar pointer mac to start of MAC address array */
	in_mac_addr = ether_aton((char* ) argv[4]);
	mac = (unsigned char *) in_mac_addr->ether_addr_octet;
	if(mac == NULL)
	{printf ("\nError: incorrect specified MAC address. \n\n"); exit(1);}

    if(argc > 5)
    {
        /* Lets try and compile the program */
        if(pcap_compile(descr,&fp,argv[2],0,netp) == -1)
        { fprintf(stderr,"Error calling pcap_compile\n"); exit(1); }
	
        /* set the compiled program as the filter */
        if(pcap_setfilter(descr,&fp) == -1)
        { fprintf(stderr,"Error setting filter\n"); exit(1); }
    }

    /* ... and loop */ 
    pcap_loop(descr,atoi(argv[1]),packet_parser,args);

	/* print results */
    printf("\nTCP packets count: %d \n", tcp_count);
    printf("UDP packets count: %d \n", udp_count);

    printf("\nSpecified MAC address : %.2x:%.2X:%.2X:%.2X:%.2X:%.2X\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    printf("\nSpecified MAC address sent packets count: %d \n", mac_scount);
    printf("Specified MAC address received packets count: %d \n", mac_dcount);

    printf("\nFinished\n\n");
    return 0;
}
