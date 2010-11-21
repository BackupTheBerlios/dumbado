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

/* la cabecera tcpdump (ether.h) define ETHER_HDRLEN) */
#ifndef ETHER_HDRLEN 
#define ETHER_HDRLEN 14
#endif

/* prototipos de las funciones "handle" para cabeceras ethernet y IP */
u_int16_t handle_ethernet
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        paquete);
u_char* handle_IP
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        paquete);


/* Estructura de una cabecera IP */
struct ip_mio {
	u_int8_t	ip_vhl;		/* longitud cabecera, versión */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* tipo de servicio */
	u_int16_t	ip_len;		/* longitud total */
	u_int16_t	ip_id;		/* identificación */
	u_int16_t	ip_off;		/* campo de desplazamiento del fragmento */
#define	IP_DF 0x4000			/* flag "no fragmentar" */
#define	IP_MF 0x2000			/* flag "más fragmentos" */
#define	IP_OFFMASK 0x1fff		/* máscara para fragmentar bits */
	u_int8_t	ip_ttl;		/* tiempo de vida */
	u_int8_t	ip_p;		/* protocolo */
	u_int16_t	ip_sum;		/* checksum */
	struct in_addr ip_orig;
	struct in_addr ip_dst;	/* direcciones origen y destino */
};

/* función de callback que analizará la cabecera ethernet */
void callback_mio(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        paquete)
{
   u_int16_t tipo = handle_ethernet(args,pkthdr,paquete);
	
/* handle de paquetes IP. Otros handlers pueden añadirse aquí */
    if(tipo == ETHERTYPE_IP)
    {
        handle_IP(args,pkthdr,paquete);
    }
}

u_char* handle_IP
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        paquete)
{
    const struct ip_mio* ip;
    u_int longitud = pkthdr->len;
    u_int caplen,off,version;
    int len;

    /* salta la cabecera ethernet */
    ip = (struct ip_mio*)(paquete + sizeof(struct ether_header));
    longitud -= sizeof(struct ether_header);

   /* comprueba si el paquete tiene la longitud correcta */
    if (longitud < sizeof(struct ip_mio))
    {
        printf("ip truncada %d",longitud);
        return NULL;
    }

	len = ntohs(ip->ip_len);
    caplen = IP_HL(ip); /* longitud de la cabecera */
    version = IP_V(ip);/* versión ip */
	
    /* comprueba versión */
    if(version != 4)
    {
      fprintf(stdout,"Versión desconocida %d\n",version);
      return NULL;
    }

    /* comprueba longitud cabecera */
    if(caplen < 5 )
    {
        fprintf(stdout,"longitud cabecera errónea %d \n",caplen);
    }

    /* comprueba la longitud del paquete */
    if(longitud < len)
        printf("\nIP truncada - faltan %d bytes\n",len - longitud);

    /* comprueba si tenemos el primer fragmento */
    off = ntohs(ip->ip_off);
    if((off & 0x1fff) == 0 )/* no hay 1's en los primeros 13 bits */
    {
		/* muestra ORIGEN DESTINO caplen version len */        
		fprintf(stdout,"IP: ");
        fprintf(stdout,"%s ",
                inet_ntoa(ip->ip_orig));
        fprintf(stdout,"%s %d %d %d %d\n",
                inet_ntoa(ip->ip_dst),
                caplen,version,len,off);
    }

    return NULL;
}

/* procesa paquetes ethernet */
u_int16_t handle_ethernet
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        paquete)
{
    u_int eth_caplen = pkthdr->caplen;
    u_int eth_longitud = pkthdr->len;
    struct ether_header *eptr;  /* net/ethernet.h */
    u_short ether_tipo;

    if (eth_caplen < ETHER_HDRLEN)
    {
        fprintf(stdout,"Longitud del paquete menor que la\nlongitud de la cabecera ethernet\n");
        return -1;
    }

    /* procesamos la cabecera ethernet... */
    eptr = (struct ether_header *) paquete;
    ether_tipo = ntohs(eptr->ether_type);

    /* mostramos ORIGEN DESTINO TIPO LONGITUD */
    fprintf(stdout,"ETH: ");
    fprintf(stdout,"%s "
            ,ether_ntoa((struct ether_addr*)eptr->ether_shost));
    fprintf(stdout,"%s "
            ,ether_ntoa((struct ether_addr*)eptr->ether_dhost));

    /* comprueba si el paquete es IP */
    if (ether_tipo == ETHERTYPE_IP)
    {
        fprintf(stdout,"(IP)");
    }else {
    /*desconocido (todo lo que no sea lo anterior...) */
        fprintf(stdout,"(?)");
    }
    fprintf(stdout," %d\n",eth_longitud);

    return ether_tipo;
}


int main(int argc,char **argv)
{ 
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    struct bpf_program fp;      /* estructura del programa BPF compilado */
    bpf_u_int32 masc;          /* mascara */
    bpf_u_int32 la_red;           /* ip */
    u_char* args = NULL;

    /* de momento pasamos las opciones de filtrado como una cadena */
    if(argc < 3){ 
        fprintf(stdout,"Uso: %s <interfaz> <numero de paquetes> <\"cadena filtro\">\n",argv[0]);
        return 0;
    }

    /* busca interfaz util... */
    /*dev = pcap_lookupdev(errbuf); 
     * DE MOMENTO SE ENTRA LA INTERFAZ COMO OPCIÓN(eth0, eth1...) */
    dev = argv[1];

    /*NO SE NECESITA DE MOMENTO */
    /*if(dev == NULL)
    { printf("%s\n",errbuf); exit(1); }*/

    /* pregunta a pcap por la dirección de red y la máscara de la tarjeta */
    pcap_lookupnet(dev,&la_red,&masc,errbuf);

    /* abre la interfaz en modo lectura, por defecto, en modo promiscuo */
    descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
    if(descr == NULL)
    { printf("pcap_open_live(): %s\n",errbuf); exit(1); }


    if(argc > 3)
    {
        /* Tratamos de compilar el filtro */
        if(pcap_compile(descr,&fp,argv[3],0,la_red) == -1)
        { fprintf(stderr,"Error en la llamada a pcap_compile\n"); exit(1); }

        /* inicializa el programa compilado como filtro */
        if(pcap_setfilter(descr,&fp) == -1)
        { fprintf(stderr,"Error inicializando el filtro\n"); exit(1); }
    }

    /* bucle */ 
    pcap_loop(descr,atoi(argv[2]),callback_mio,args);

    fprintf(stdout,"\nfinalizado\n");
    return 0;
}

