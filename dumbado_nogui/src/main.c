/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*- */
/*
 * main.c
 * Copyright (C) Ricard Pradell Buxó 2010 <rpradell@uoc.edu>
 * 
 * dumbado_noGUI is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * dumbado_noGUI is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <net/ethernet.h>
#include <netinet/ether.h> 
#include <netinet/ip.h> 

/* tcpdump header (ether.h) defines ETHER_HDRLEN) */
#ifndef ETHER_HDRLEN 
#define ETHER_HDRLEN 14
#endif

/* handle function prototypes for IP and ethernet headers */
u_int16_t handle_ethernet
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet);
u_char* handle_IP
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet);


/* IP header struct */
struct my_ip {
	u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* type of service */
	u_int16_t	ip_len;		/* total length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment 's offset field */
#define	IP_DF 0x4000			/* "don't fragment" flag */
#define	IP_MF 0x2000			/* "more fragments" flag */
#define	IP_OFFMASK 0x1fff		/* mask for bit fragmentation */
	u_int8_t	ip_ttl;		/* time to live */
	u_int8_t	ip_p;		/* protocol */
	u_int16_t	ip_sum;		/* checksum */
	struct in_addr ip_orig;
	struct in_addr ip_dst;	/* origin and destiny adresses */
};

/* callback function that will analyze ethernet header */
void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
   u_int16_t type = handle_ethernet(args,pkthdr,packet);
	
/* IP packet handler. Other handles can be added here */
    if(type == ETHERTYPE_IP)
    {
        handle_IP(args,pkthdr,packet);
    }
}

u_char* handle_IP
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
    const struct my_ip* ip;
    u_int length = pkthdr->len;
    u_int caplen,off,version;
    int len;

    /* skips ethernet header */
    ip = (struct my_ip*)(packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header);

   /* checks if packet has the correct size */
    if (length < sizeof(struct my_ip))
    {
        printf("truncated ip %d",length);
        return NULL;
    }

	len = ntohs(ip->ip_len);
    caplen = IP_HL(ip); /* header length */
    version = IP_V(ip);/* ip version*/
	
    /* checks version */
    if(version != 4)
    {
      fprintf(stdout,"Unknown version %d\n",version);
      return NULL;
    }

    /* checks header length */
    if(caplen < 5 )
    {
        fprintf(stdout,"wrong header length %d \n",caplen);
    }

    /* checks packet length */
    if(length < len)
        printf("\ntruncated IP - %d bytes missing\n",len - length);

    /* checks if we have the first fragment */
    off = ntohs(ip->ip_off);
    if((off & 0x1fff) == 0 )/* no 1's in the first 13 bits */
    {
		/* shows ORIG DEST caplen version len */        
		fprintf(stdout,"IP: ");
        fprintf(stdout,"%s ",
                inet_ntoa(ip->ip_orig));
        fprintf(stdout,"%s %d %d %d %d\n",
                inet_ntoa(ip->ip_dst),
                caplen,version,len,off);
    }

    return NULL;
}

/* process ethernet packets */
u_int16_t handle_ethernet
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
    u_int eth_caplen = pkthdr->caplen;
    u_int eth_length = pkthdr->len;
    struct ether_header *eptr;  /* net/ethernet.h */
    u_short ether_type;

    if (eth_caplen < ETHER_HDRLEN)
    {
        fprintf(stdout,"Packet length shorter than ethernet header\n");
        return -1;
    }

    /* process ethernet header... */
    eptr = (struct ether_header *) packet;
    ether_type = ntohs(eptr->ether_type);

    /* show ORIG DEST TYPE LENGTH */
    fprintf(stdout,"ETH: ");
    fprintf(stdout,"%s "
            ,ether_ntoa((struct ether_addr*)eptr->ether_shost));
    fprintf(stdout,"%s "
            ,ether_ntoa((struct ether_addr*)eptr->ether_dhost));

    /* checks if packet is IP */
    if (ether_type == ETHERTYPE_IP)
    {
        fprintf(stdout,"(IP)");
    }else {
    /*unknown (everything else...) */
        fprintf(stdout,"(?)");
    }
    fprintf(stdout," %d\n",eth_length);

    return ether_type;
}


int main(int argc,char **argv)
{ 
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    struct bpf_program fp;      /* compiled BPF program struct */
    bpf_u_int32 mask;          /* mask */
    bpf_u_int32 net;           /* ip */
    u_char* args = NULL;

    /* we pass filtering options as a string by now */
    if(argc < 3){ 
        fprintf(stdout,"Usage: %s <interface> <packets> <\"filter string\">\n",argv[0]);
        return 0;
    }

    /* search useful interfaces... */
    /*dev = pcap_lookupdev(errbuf); 
     * WE ENTER INTERFACES AS AN OPTION BY NOW (eth0, eth1...) */
    dev = argv[1];

    /*NOT NEEDED BY NOW */
    /*if(dev == NULL)
    { printf("%s\n",errbuf); exit(1); }*/

    /* asks pcap device's net adress and mask */
    pcap_lookupnet(dev,&net,&mask,errbuf);

    /* opens interface in read mode. By default, promiscuous mode */
    descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
    if(descr == NULL)
    { printf("pcap_open_live(): %s\n",errbuf); exit(1); }


    if(argc > 3)
    {
        /* Try to compile filter */
        if(pcap_compile(descr,&fp,argv[3],0,net) == -1)
        { fprintf(stderr,"Error when calling pcap_compile\n"); exit(1); }

        /* initiates compiled program as a filter */
        if(pcap_setfilter(descr,&fp) == -1)
        { fprintf(stderr,"Error initializing filter\n"); exit(1); }
    }

    /* loop */ 
    pcap_loop(descr,atoi(argv[2]),my_callback,args);

    fprintf(stdout,"\nfinished\n");
    return 0;
}

