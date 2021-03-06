/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*- */
/*
 * main.c
 * Copyright (C) Ricard Pradell 2010 <rpradell@uoc.edu>
 * 
 * dumbado is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * dumbado is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "callbacks.h"

/*
 * Standard gettext macros.
 */
#ifdef ENABLE_NLS
#  include <libintl.h>
#  undef _
#  define _(String) dgettext (PACKAGE, String)
#  ifdef gettext_noop
#    define N_(String) gettext_noop (String)
#  else
#    define N_(String) (String)
#  endif
#else
#  define textdomain(String) (String)
#  define gettext(String) (String)
#  define dgettext(Domain,Message) (Message)
#  define dcgettext(Domain,Message,Type) (Message)
#  define bindtextdomain(Domain,Directory) (Domain)
#  define _(String) (String)
#  define N_(String) (String)
#endif

#define BUF_SIZE 256
#define MAX_NUM 18446000000000000000ULL

/* tcpdump header (ether.h) defines ETHER_HDRLEN) */
#ifndef ETHER_HDRLEN 
#define ETHER_HDRLEN 14
#endif

/* declared global, used elsewhere */
static GladeXML *gxml;
static pcap_t* descr;

/* counters */
unsigned long long packet_counter = 0;
unsigned long long ip_counter = 0;
unsigned long long tcp_counter = 0;
unsigned long long udp_counter = 0;
unsigned long long arp_counter = 0;
unsigned long long rarp_counter = 0;
unsigned long long icmp_counter = 0;
unsigned long long unk_ip_counter = 0;
unsigned long long unk_eth_counter = 0;

/* IP header struct*/
struct my_ip {
	u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* service type */
	u_int16_t	ip_len;		/* ltotal length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment's offset field */
#define	IP_DF 0x4000			/* flag "don't fragment" */
#define	IP_MF 0x2000			/* flag "more fragments" */
#define	IP_OFFMASK 0x1fff		/* mask for bit fragment */
	u_int8_t	ip_ttl;		/* time to live */
	u_int8_t	ip_p;		/* protocol */
	u_int16_t	ip_sum;		/* checksum */
	struct in_addr ip_orig;
	struct in_addr ip_dst;	/* origin and destination addresses */
};

/* PROTOTYPES */
int pcap_dloff(pcap_t *pd);

/* ethernet headers handle function prototypes...*/
u_int16_t handle_ethernet
        (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);

/* ...and IP */
u_char* handle_IP
        (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);

/* callback function that will parse ethernet header */
void my_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);

/* gets interfaces */
GList* createListInterfaces(GString *err_str);

/* Empties list */
void emptyListInterfaces(GList *if_list);

/* fills combo with found interfaces */
void fill_combo(void);

/* check data codification(UTF8) */
char *validate_utf8(char *data);

/* prints a string in GtkTextBuffer */
void print_TextView(GtkTextView *textview, GtkTextBuffer *textbuf, char *data);

/* prints statistics */
int show_statistics(void);

/* counters to 0 */
void counters_to_zero(void);

/* END_PROTOTYPES */

GtkWidget* create_window (void)
{
	GtkWidget *window;
	
	gxml = glade_xml_new (GLADE_FILE, NULL, NULL);
	
	/* This is important */
	/* Anjuta IDE wrote this...*/
	glade_xml_signal_autoconnect (gxml);
	window = glade_xml_get_widget (gxml, "window");
	
	return window;
}


int main (int argc, char *argv[])
{
 	GtkWidget *window;
	GtkWidget *button_start;
	GtkWidget *button_finish;
	GtkWidget *statusbar;
	GtkTextBuffer *textbuf;
	GtkWidget *textview;
	GtkWidget *menu_save;
	
#ifdef ENABLE_NLS
	bindtextdomain (GETTEXT_PACKAGE, PACKAGE_LOCALE_DIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);
#endif

	gtk_set_locale ();
	gtk_init (&argc, &argv);

	window = create_window ();
	gtk_window_set_title ((GtkWindow*) window, "dumbado: Graphic  network packet analyzer");
	gtk_widget_show (window);
	

	/* Are you root? */
	if (getuid()) {
		gest_err_msg ("Only root can use dumbado. Quitting");
		return 1;
    }

	fill_combo();
	
	/* WIDGETS */
	button_start = glade_xml_get_widget (gxml, "button_start");
	button_finish = glade_xml_get_widget (gxml, "button_finish");
	statusbar = glade_xml_get_widget (gxml, "statusbar1");
	textview = glade_xml_get_widget (gxml, "textview_capture");
	textbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview));
	menu_save = glade_xml_get_widget (gxml, "menu_save");
	
	/* TAGS */
	gtk_text_buffer_create_tag(textbuf, "gray_bg", "background", "gray", NULL);
	gtk_text_buffer_create_tag(textbuf, "blue_fg", "foreground", "blue", NULL);
	gtk_text_buffer_create_tag(textbuf, "red_fg", "foreground", "red", NULL);
	gtk_text_buffer_create_tag(textbuf, "bold", "weight", PANGO_WEIGHT_BOLD, NULL);
	gtk_text_buffer_create_tag(textbuf, "lmarg", "left_margin", 5, NULL);
	gtk_text_buffer_create_tag(textbuf, "lmarg_more", "left_margin", 10, NULL);
	
	/* SIGNALS */
	g_signal_connect(G_OBJECT(button_start), "clicked", 
	       G_CALLBACK(button_start_click), G_OBJECT(statusbar));
	g_signal_connect(G_OBJECT(button_finish), "clicked", 
           G_CALLBACK(button_finish_click), G_OBJECT(statusbar));
	gtk_signal_connect (GTK_OBJECT (window), "delete_event",
                        GTK_SIGNAL_FUNC (delete_event), NULL);
	g_signal_connect(G_OBJECT(window), "destroy",
        G_CALLBACK(on_window_destroy), G_OBJECT(window));
	
	gtk_main ();
	return 0;
}

/* callback function that will parse ethernet header */
void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
	if (packet_counter < MAX_NUM)
	{
		packet_counter++;
	}
    u_int16_t type = handle_ethernet(args, pkthdr, packet);

	/* IP packet handler. Other handlers may be added here */
    if(type == ETHERTYPE_IP)
    {
        handle_IP(args, pkthdr, packet);
    }
}

/* process ethernet packets */
u_int16_t handle_ethernet
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    u_int eth_headlen = pkthdr->caplen;
    u_int eth_length = pkthdr->len;
    struct ether_header *eptr;  /* net/ethernet.h */
    u_short ether_type;
	GtkWidget *textview;
	GtkTextBuffer *textbuf;
	char buf[BUF_SIZE];
	char *ether_shost;
	char *ether_dhost;
	
    if (eth_headlen < ETHER_HDRLEN)
    {
		gest_err_msg ("Packet length shorter than\nethernet header length\n. Aborting");
        return -1;
    }

    /* processing ethernet header... */
    eptr = (struct ether_header *) packet;
    ether_type = ntohs(eptr->ether_type);

    /* print origin, destination, type, length */
	textview = glade_xml_get_widget (gxml, "textview_capture");
	textbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview));
	print_TextView ((GtkTextView*)textview, textbuf, "Ethernet Packet:\n");
	print_TextView ((GtkTextView*)textview, textbuf, "Origin MAC: ");
	ether_shost = ether_ntoa((struct ether_addr*)eptr->ether_shost);
	print_TextView ((GtkTextView*)textview, textbuf, ether_shost);
	ether_dhost = ether_ntoa((struct ether_addr*)eptr->ether_dhost);
	print_TextView ((GtkTextView*)textview, textbuf, " Destination MAC: ");
	print_TextView ((GtkTextView*)textview, textbuf, ether_dhost);
	print_TextView ((GtkTextView*)textview, textbuf, "\n");

    /* checks if packet is IP */
	switch (ether_type)
	{
		case ETHERTYPE_IP:
			print_TextView ((GtkTextView*)textview, textbuf, " Packet is IP ");
			break;
		case ETHERTYPE_ARP:
			if (arp_counter < MAX_NUM)
				{
					arp_counter++;
				}
			print_TextView ((GtkTextView*)textview, textbuf, " Packet is ARP ");
			break;
		case ETHERTYPE_REVARP:
			if (rarp_counter < MAX_NUM)
				{
					rarp_counter++;
				}
			print_TextView ((GtkTextView*)textview, textbuf, "Packet is RARP ");
			break;
		default:
			/*unknown (anything that doesn't match the above criteria...) */
			if (unk_eth_counter< MAX_NUM)
				{
					unk_eth_counter++;
				}
			print_TextView ((GtkTextView*)textview, textbuf, " Packet type unknown ");
			break;
	}
	
	print_TextView ((GtkTextView*)textview, textbuf, " Length: ");
	snprintf(buf, BUF_SIZE, "%d", eth_length);
	print_TextView ((GtkTextView*)textview, textbuf, buf);
	print_TextView ((GtkTextView*)textview, textbuf, "\n");

    return ether_type;
}

/* process IP packets */
u_char* handle_IP
        (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    const struct my_ip* ip;
    u_int length = pkthdr->len;
    u_int headlen, off, version;
    int len;
	char buf[BUF_SIZE];
	GtkWidget *textview;
	GtkTextBuffer * textbuf;
	
	if (ip_counter < MAX_NUM)
	{
		ip_counter++;
	}
	textview = glade_xml_get_widget (gxml, "textview_capture");
	textbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview));
	
    /* jumps ethernet header */
    ip = (struct my_ip*)(packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header);
	
    /* checks if packet has the correct size */
    if (length < sizeof(struct my_ip))
    {
		print_TextView ((GtkTextView*)textview, textbuf, "ip truncated: ");
		snprintf(buf, BUF_SIZE, "%d", length);
		print_TextView ((GtkTextView*)textview, textbuf, buf);
		print_TextView ((GtkTextView*)textview, textbuf, "\n");
        return NULL;
    }

    len = ntohs(ip->ip_len);
    headlen = IP_HL(ip); /* header length */
    version = IP_V(ip);/* ip version */

    /* checks version */
    if(version != 4)
    {
		print_TextView ((GtkTextView*)textview, textbuf, "Unknown version: ");
		snprintf(buf, BUF_SIZE, "%d", version);
		print_TextView ((GtkTextView*)textview, textbuf, buf);
		print_TextView ((GtkTextView*)textview, textbuf, "\n");
      	return NULL;
    }

    /* checks header length */
    if(headlen < 5 )
    {
		print_TextView ((GtkTextView*)textview, textbuf, "Wrong header length: ");
		snprintf(buf, BUF_SIZE, "%d", headlen);
		print_TextView ((GtkTextView*)textview, textbuf, buf);
		print_TextView ((GtkTextView*)textview, textbuf, "\n");
    }

    /* checks packet length */
    if(length < len)
	{
		print_TextView ((GtkTextView*)textview, textbuf, "IP truncated: ");
		snprintf(buf, BUF_SIZE, "%d", len - length);
		print_TextView ((GtkTextView*)textview, textbuf, buf);
		print_TextView ((GtkTextView*)textview, textbuf, " bytes missing\n");
	}
	
    /* checks if we have the first fragment */
    off = ntohs(ip->ip_off);
    if((off & 0x1fff) == 0 )/* there are no 1's in the first 13 bits */
    {
		/* prints origin, destination, headlen, version, len */
		print_TextView ((GtkTextView*)textview, textbuf, "IP Packet: ");
		print_TextView ((GtkTextView*)textview, textbuf, "\n");
		print_TextView ((GtkTextView*)textview, textbuf, "Origin IP: ");
		print_TextView ((GtkTextView*)textview, textbuf, inet_ntoa(ip->ip_orig));
		print_TextView ((GtkTextView*)textview, textbuf, " Destination IP: ");
		print_TextView ((GtkTextView*)textview, textbuf, inet_ntoa(ip->ip_dst));
		print_TextView ((GtkTextView*)textview, textbuf, " header: ");
		snprintf(buf, BUF_SIZE, "%d", headlen*4);
		print_TextView ((GtkTextView*)textview, textbuf, buf);
		print_TextView ((GtkTextView*)textview, textbuf, " bytes ");
		print_TextView ((GtkTextView*)textview, textbuf, "Version: ");
		snprintf(buf, BUF_SIZE, "%d", version);
		print_TextView ((GtkTextView*)textview, textbuf, buf);
		print_TextView ((GtkTextView*)textview, textbuf, " Length: ");
		snprintf(buf, BUF_SIZE, "%d", len);
		print_TextView ((GtkTextView*)textview, textbuf, buf);
		print_TextView ((GtkTextView*)textview, textbuf, "\n");
		
		
		/* Protocol */
		switch (ip->ip_p){
			case 1:{
				if (icmp_counter < MAX_NUM)
				{
					icmp_counter++;
				}
				print_TextView ((GtkTextView*)textview, textbuf, "Protocol: ICMP ");
				print_TextView ((GtkTextView*)textview, textbuf, "\n");
				break;
			}
			case 6:{
				if (tcp_counter < MAX_NUM)
				{
					tcp_counter++;
				}
				print_TextView ((GtkTextView*)textview, textbuf, "Protocol: TCP ");
				print_TextView ((GtkTextView*)textview, textbuf, "\n");
				
				break;
			}
			case 17:{
				if (udp_counter < MAX_NUM)
				{
					udp_counter++;
				}
				print_TextView ((GtkTextView*)textview, textbuf, "Protocol: UDP ");
				print_TextView ((GtkTextView*)textview, textbuf, "\n");
				break;
			}
			default:{
				if (unk_ip_counter < MAX_NUM)
				{
					unk_ip_counter++;
				}
				print_TextView ((GtkTextView*)textview, textbuf, "Protocol: Unknown ");
				print_TextView ((GtkTextView*)textview, textbuf, "\n");
				break;
			}
		}
    }

    return NULL;
}

int loop_capture(int argc, char *interface, char *filter, char *num_packets)
 { 
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;      /* struct BPF compiled program */
    bpf_u_int32 mask;          /* mask */
    bpf_u_int32 net;           /* ip */
    u_char* args = NULL;
	char buf[1024];
	int link_type;

	counters_to_zero();
    dev = interface;

    /* asks pcap about interface network address and mask */
    pcap_lookupnet(dev,&net,&mask,errbuf);

    /* opens interface in read mode, by default, promiscuous mode */
    descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
    if(descr == NULL)
    { 
		snprintf(buf, 1024, "pcap_open_live() error\nCould not open interface\nPCAP: %s", errbuf);
		gest_err_msg (buf);
		activate_deactivate();
		return 1;
	}

    if(filter != NULL)
    {
        /* Trying to compile filter */
        if(pcap_compile(descr,&fp,filter,0,net) == -1)
		{
			gest_err_msg ("pcap_compile() error\nCould not compile filter.\nCheck syntax");
			return 1;
		}

        /* initiates compiled program as filter */
        if(pcap_setfilter(descr,&fp) == -1)
        {
			gest_err_msg ("Error initializing filter");
			return 1;
		}
    }

	/* We are focused onto ethernet by now, but depending
	 * on what this function returns, we can discriminate
	 * different link layer protocol types */
	link_type = pcap_dloff(descr);
	 
    /* loop */ 
	pcap_loop(descr,atoi(num_packets),my_callback, args);
	 
	 if (show_statistics() != 0)
	 {
		 /* error messages delegated to function */
	 }
    return 0;
}

/* gets interface list */
GList* createListInterfaces(GString *err_str)
{
    GList *list = NULL;
    pcap_if_t *ifaces_list = NULL;
    pcap_if_t *ifaces_actual;
    char pcap_errstr[1024]="";
	char buf[1024];
	

    g_string_assign(err_str, "");

    if (pcap_findalldevs(&ifaces_list, pcap_errstr) < 0)
      {
          /* could not get list */
		  snprintf(buf, 1024, "Error trying to build interface list\nPCAP: %s", pcap_errstr);
		  gest_err_msg (buf);
          return NULL;
      }

    /* Ordered interface list */
    for (ifaces_actual=ifaces_list ; ifaces_actual ; ifaces_actual = ifaces_actual->next)
      {
	      list = g_list_append(list, g_strdup(ifaces_actual->name));
      }
	
    /* frees list devices */
    pcap_freealldevs(ifaces_actual);

    /* returns our list */
    return list;
}

/* Empties list */
static void emptyListInterfaces_cb(gpointer data, gpointer user_data)
{
    g_free (data);
	return;
}

void emptyListInterfaces(GList *if_list)
{
    if (if_list)
      {
          g_list_foreach (if_list, emptyListInterfaces_cb, NULL);
          g_list_free (if_list);
      }
	return;
}

/* Adds interfaces to combo */
void fill_combo(void)
{ 
	GtkWidget *combo;
    GList *interfaces;
	char buf[1024];
	GString *err_str = g_string_new ("");
	
    interfaces = createListInterfaces(err_str);
    if (!interfaces)
      {
		  snprintf(buf, 1024, "Could not find valid interfaces\nPCAP: %s", (char*)err_str);
		  gest_err_msg (buf);
          return;
      }
    
    combo = glade_xml_get_widget(gxml, "combobox_iface");

    while (interfaces)
      {
		   gtk_combo_box_append_text(GTK_COMBO_BOX(combo), (gchar *) (interfaces->data));
           interfaces = interfaces->next;
      }
	gtk_combo_box_set_active (GTK_COMBO_BOX (combo), 0);
    emptyListInterfaces(interfaces);
	return;
}

/* prints a string on GtkTextBuffer */
void print_TextView (GtkTextView *textview, GtkTextBuffer *textbuf, char *data)
{
	GtkTextIter iter;
	gchar *unicode;
	
	if((unicode = validate_utf8(data)) == NULL){
		gtk_text_buffer_insert_with_tags_by_name (textbuf, 
												  &iter, 
												  "invalid data\n", 
												  -1,
												  "red_fg",
												  "bold",
												  NULL);
		return;
	}
	
	if(strcmp(unicode, "Ethernet Packet:\n") == 0)
	{
		gtk_text_buffer_get_end_iter(textbuf, &iter);
		gtk_text_buffer_insert_with_tags_by_name (textbuf, 
												  &iter,
												  unicode, 
												  -1, 
												  "gray_bg", 
												  "bold", 
												  NULL);
		gtk_text_view_scroll_to_iter (textview, 
									  &iter, 
									  0.0, 
									  FALSE, 
									  0.0, 
									  0.0);
	}else if(strcmp(unicode, "Origin MAC: ") == 0){
		gtk_text_buffer_get_end_iter(textbuf, &iter);
		gtk_text_buffer_insert_with_tags_by_name (textbuf, 
												  &iter, 
												  unicode, 
												  -1, 
												  "lmarg", 
												  NULL);
		gtk_text_view_scroll_to_iter (textview, 
									  &iter, 
									  0.0, 
									  FALSE, 
									  0.0, 
									  0.0);
	}else if(strcmp(unicode, "IP Packet: ") == 0)
	{
		gtk_text_buffer_get_end_iter(textbuf, &iter);
		gtk_text_buffer_insert_with_tags_by_name (textbuf, 
												  &iter, 
												  unicode, 
												  -1,
												  "blue_fg",
												  "lmarg", 
												  NULL);
		gtk_text_view_scroll_to_iter (textview, 
									  &iter, 
									  0.0, 
									  FALSE, 
									  0.0, 
									  0.0);
	}else if(strcmp(unicode, "Origin IP: ") == 0)
	{
		gtk_text_buffer_get_end_iter(textbuf, &iter);
		gtk_text_buffer_insert_with_tags_by_name (textbuf, 
												  &iter, 
												  unicode, 
												  -1,
												  "lmarg_more",
												  NULL);
		gtk_text_view_scroll_to_iter (textview, 
									  &iter, 
									  0.0, 
									  FALSE, 
									  0.0, 
									  0.0);
	}else if(strcmp(unicode, "Protocol: ICMP ") == 0)
	{
		gtk_text_buffer_get_end_iter(textbuf, &iter);
		gtk_text_buffer_insert_with_tags_by_name (textbuf, 
												  &iter, 
												  unicode, 
												  -1,
												  "lmarg_more",
												  "red_fg",
												  NULL);
		gtk_text_view_scroll_to_iter (textview, 
									  &iter, 
									  0.0, 
									  FALSE, 
									  0.0, 
									  0.0);
	}else if(strcmp(unicode, "Protocol: TCP ") == 0)
	{
		gtk_text_buffer_get_end_iter(textbuf, &iter);
		gtk_text_buffer_insert_with_tags_by_name (textbuf, 
												  &iter, 
												  unicode, 
												  -1,
												  "lmarg_more",
												  "red_fg",
												  NULL);
		gtk_text_view_scroll_to_iter (textview, 
									  &iter, 
									  0.0, 
									  FALSE, 
									  0.0, 
									  0.0);
	}else if(strcmp(unicode, "Protocol: UDP ") == 0)
	{
		gtk_text_buffer_get_end_iter(textbuf, &iter);
		gtk_text_buffer_insert_with_tags_by_name (textbuf, 
												  &iter, 
												  unicode, 
												  -1,
												  "lmarg_more",
												  "red_fg",
												  NULL);
		gtk_text_view_scroll_to_iter (textview, 
									  &iter, 
									  0.0, 
									  FALSE, 
									  0.0, 
									  0.0);
	}else{
		gtk_text_buffer_get_end_iter(textbuf, &iter);
		gtk_text_buffer_insert (textbuf, 
								&iter, 
								unicode, 
								-1);
		gtk_text_view_scroll_to_iter (textview, 
									  &iter, 
									  0.0, 
									  FALSE, 
									  0.0, 
									  0.0);
	}
	
	/* refreshes screen */
	while (gtk_events_pending ())
    gtk_main_iteration ();
	return;
}

/* check data codification (UTF8) */
char *validate_utf8 (char *data) 
{
	const gchar *final;
	char *unicode = NULL;

	unicode = data;
	if(!g_utf8_validate (data, -1, &final)) {
		/* if pointer is at "final" we are in the beginning of the string,
		 * we have no valid text to print */
		if(final == unicode) return(NULL);

		/* cuts invalid part so we didn't end up with nothing */
		unicode = (char *)final;
		*unicode = 0;
		unicode = data;
	}
	return(unicode);
}

/* error and messages management */
void gest_err_msg (const char *msg)
{
	GtkWidget *window_err_msg = NULL;
	GtkWidget *dialog;
	gchar *unicode = NULL;

	if((unicode = validate_utf8 ((char *)msg)) == NULL)
		return;

	dialog = gtk_message_dialog_new(GTK_WINDOW (window_err_msg), GTK_DIALOG_MODAL, 
                                   GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "%s", unicode);
	gtk_window_set_position(GTK_WINDOW (dialog), GTK_WIN_POS_CENTER);
	gtk_window_set_title ((GtkWindow*) (dialog), "Warning:");

	gtk_dialog_run(GTK_DIALOG (dialog));

	gtk_widget_destroy(dialog);
	return;
}

void return_to_zero(void){
	GtkWidget *textview;
	GtkTextBuffer *textbuf;
	
	textview = glade_xml_get_widget (gxml, "textview_capture");
	textbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview));
	gtk_text_buffer_set_text(textbuf, "\0",-1);
}

/* activates or deactivates buttons */
void activate_deactivate(void)
{
	GtkWidget* but_start;
	GtkWidget* but_fin;
	
	but_start = glade_xml_get_widget (gxml, "button_start");
	but_fin = glade_xml_get_widget (gxml, "button_finish");
	
	if (GTK_WIDGET_IS_SENSITIVE(but_start) == TRUE)
	{
		gtk_widget_set_sensitive(but_start, FALSE);
	}else{
		gtk_widget_set_sensitive(but_start, TRUE);
	}
	
	if (GTK_WIDGET_IS_SENSITIVE(but_fin) == TRUE)
	{
		gtk_widget_set_sensitive(but_fin, FALSE);
	}else{
		gtk_widget_set_sensitive(but_fin, TRUE);
	}
}

int f_pass_parameters(struct st_parameters *parameters){
	GtkWidget *combo;
	GtkWidget *entry_filter; 
	GtkWidget *entry_numPackets;
	char *text;
	int ret;
	
	combo = glade_xml_get_widget (gxml, "combobox_iface");
	entry_filter = glade_xml_get_widget (gxml, "entry_filter");
	entry_numPackets= glade_xml_get_widget (gxml, "entry_packets");
	
	/* interface */
	text = (char*)gtk_combo_box_get_active_text(GTK_COMBO_BOX(combo));
	if(text != NULL) 
	{
		strcpy(parameters->interface, text);
	}
	/* filter rules */
	text = (char*)gtk_entry_get_text(GTK_ENTRY(entry_filter));
	if (strcmp(text, "")!= 0)
	{
		strcpy(parameters->filter, text);
	}
	
	/* captured packets */
	text = (char*)gtk_entry_get_text(GTK_ENTRY(entry_numPackets));
	if (strcmp(text,"") != 0){
		ret = atoi(text);
		if (ret == 0){
			gest_err_msg ("Invalid number of packets.\nValid characters:[0-9].\nFalling to default option.");
		}else{
			strcpy(parameters->numPackets, text);
		}
	}
	return 0;
}

int pcap_dloff(pcap_t *pd)
{
	int offset = -1;
	
	switch (pcap_datalink(pd)) {
	case DLT_EN10MB:
		offset = 14;
		break;
	case DLT_IEEE802:
		offset = 22;
		break;
	case DLT_FDDI:
		offset = 21;
		break;
#ifdef DLT_LOOP
	case DLT_LOOP:
#endif
	case DLT_NULL:
		offset = 4;
		break;
	default:
		break;
	}
	return (offset);
}

/* Shows a save file dialog box, returns file name */
gchar *which_file(void)
{
        GtkWidget *dialog;
        gchar *file_name=NULL;
                
        dialog = gtk_file_chooser_dialog_new ("Saving log...",
                                               NULL,
                                               GTK_FILE_CHOOSER_ACTION_SAVE,
                                               GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
                                               GTK_STOCK_SAVE, GTK_RESPONSE_OK,
                                               NULL);
                                               
        if (gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_OK)
        {
                file_name = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog));
        }
        
        gtk_widget_destroy (dialog);
        return file_name;
}

/* we've got a filename and want to save textview's content */
void write_file(gchar *file_name)
{
	GError *err = NULL;
    gchar *status;
    gchar *text;
    gboolean result;
    GtkTextBuffer *textbuff;
    GtkTextIter start, finish;
	GtkWidget *statusbar;
	GtkWidget *textview;
	
	statusbar = glade_xml_get_widget (gxml, "statusbar1");
    status = g_strdup_printf ("Saving %s...", file_name);
    gtk_statusbar_push (GTK_STATUSBAR (statusbar),
                            gtk_statusbar_get_context_id(GTK_STATUSBAR(statusbar), status), status);
    g_free (status);
    while (gtk_events_pending()) gtk_main_iteration();
    textview = glade_xml_get_widget (gxml, "textview_capture");
	
    /* unlinks textview and takes textbuffer's content */ 
    textbuff = gtk_text_view_get_buffer (GTK_TEXT_VIEW (textview));
    gtk_text_buffer_get_start_iter (textbuff, &start);
    gtk_text_buffer_get_end_iter (textbuff, &finish);
    text = gtk_text_buffer_get_text (textbuff, &start, &finish, FALSE);       
        
    /* saves */  
    result = g_file_set_contents (file_name, text, -1, &err);
        
    if (result == FALSE)
    {
		gest_err_msg ("Error saving log");
    }        
    g_free (text); 
}

void stop_loop(void)
{
	pcap_breakloop(descr);
}

void kill_pcap(void)
{
	pcap_close(descr);
}

int show_statistics(void)
{
	struct pcap_stat ps;
	GtkWidget* textview;
	GtkTextBuffer* textbuf;
	char *errbuf;
	char buf[1024];
	unsigned long long percentage;
	
	textview = glade_xml_get_widget (gxml, "textview1");
	textbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview));
	gtk_text_buffer_set_text(textbuf, "\0",-1);
	if(pcap_stats(descr,&ps) != 0)
	 {
		 errbuf = pcap_geterr(descr);
		 snprintf(buf, 1024, "pcap_stats() error\nCould not print statistics.\nPCAP: %s", errbuf);
		 gest_err_msg (buf);
		 return -1;
	 }
	if (packet_counter > 0)
	{
		print_TextView ((GtkTextView*)textview, textbuf, "PCAP STATISTICS: \n");
		print_TextView ((GtkTextView*)textview, textbuf, "Packets bypassing filter: ");
		snprintf(buf, BUF_SIZE, "%d\n", ps.ps_recv);
		print_TextView ((GtkTextView*)textview, textbuf, buf);
		print_TextView ((GtkTextView*)textview, textbuf, "Dropped packets: ");
		snprintf(buf, BUF_SIZE, "%d\n", ps.ps_drop);
		print_TextView ((GtkTextView*)textview, textbuf, buf);
		print_TextView ((GtkTextView*)textview, textbuf, "\n");
		print_TextView ((GtkTextView*)textview, textbuf, "LOG STATISTICS: \n");
		
		/* ETHERNET */
		print_TextView ((GtkTextView*)textview, textbuf, "Ethernet packets: ");
		snprintf(buf, BUF_SIZE, "%llu ", packet_counter);
		print_TextView ((GtkTextView*)textview, textbuf, buf);
		print_TextView ((GtkTextView*)textview, textbuf, "\n");
		print_TextView ((GtkTextView*)textview, textbuf, "\n");
		
		/* ARP */
		print_TextView ((GtkTextView*)textview, textbuf, "ARP packets: ");
		snprintf(buf, BUF_SIZE, "%llu ", arp_counter);
		print_TextView ((GtkTextView*)textview, textbuf, buf);
		print_TextView ((GtkTextView*)textview, textbuf, "Percentage: ");
		percentage = (arp_counter * 100/packet_counter);
		snprintf(buf, BUF_SIZE, "%llu ", percentage);
		print_TextView ((GtkTextView*)textview, textbuf, buf);
		print_TextView ((GtkTextView*)textview, textbuf, "\%\n");
		print_TextView ((GtkTextView*)textview, textbuf, "\n");
		
		/* RARP */
		print_TextView ((GtkTextView*)textview, textbuf, "RARP packets: ");
		snprintf(buf, BUF_SIZE, "%llu ", rarp_counter);
		print_TextView ((GtkTextView*)textview, textbuf, buf);
		print_TextView ((GtkTextView*)textview, textbuf, "Percentage: ");
		percentage = (rarp_counter * 100/packet_counter);
		snprintf(buf, BUF_SIZE, "%llu ", percentage);
		print_TextView ((GtkTextView*)textview, textbuf, buf);
		print_TextView ((GtkTextView*)textview, textbuf, "\%\n");
		print_TextView ((GtkTextView*)textview, textbuf, "\n");
		
		/* ETH unknown*/
		print_TextView ((GtkTextView*)textview, textbuf, "Unknown: ");
		snprintf(buf, BUF_SIZE, "%llu ", unk_eth_counter);
		print_TextView ((GtkTextView*)textview, textbuf, buf);
		print_TextView ((GtkTextView*)textview, textbuf, "Percentage: ");
		percentage = (unk_eth_counter * 100/packet_counter);
		snprintf(buf, BUF_SIZE, "%llu ", percentage);
		print_TextView ((GtkTextView*)textview, textbuf, buf);
		print_TextView ((GtkTextView*)textview, textbuf, "\%\n");
		print_TextView ((GtkTextView*)textview, textbuf, "\n");
		
		/* IP */
		if(ip_counter > 0)
		{
			print_TextView ((GtkTextView*)textview, textbuf, "IP packets: ");
			snprintf(buf, BUF_SIZE, "%llu ", ip_counter);
			print_TextView ((GtkTextView*)textview, textbuf, buf);
			print_TextView ((GtkTextView*)textview, textbuf, "Percentage: ");
			percentage = (ip_counter * 100/packet_counter);
			snprintf(buf, BUF_SIZE, "%llu ", percentage);
			print_TextView ((GtkTextView*)textview, textbuf, buf);
			print_TextView ((GtkTextView*)textview, textbuf, "\%\n");
			
			/* TCP */
			print_TextView ((GtkTextView*)textview, textbuf, "   TCP protocol: ");
			snprintf(buf, BUF_SIZE, "%llu ", tcp_counter);
			print_TextView ((GtkTextView*)textview, textbuf, buf);
			print_TextView ((GtkTextView*)textview, textbuf, "Percentage: ");
			percentage = (tcp_counter * 100/ip_counter);
			snprintf(buf, BUF_SIZE, "%llu ", percentage);
			print_TextView ((GtkTextView*)textview, textbuf, buf);
			print_TextView ((GtkTextView*)textview, textbuf, "\%\n");
			
			/* UDP */
			print_TextView ((GtkTextView*)textview, textbuf, "   UDP protocol: ");
			snprintf(buf, BUF_SIZE, "%llu ", udp_counter);
			print_TextView ((GtkTextView*)textview, textbuf, buf);
			print_TextView ((GtkTextView*)textview, textbuf, "Percentage: ");
			percentage = (udp_counter * 100/ip_counter);
			snprintf(buf, BUF_SIZE, "%llu ", percentage);
			print_TextView ((GtkTextView*)textview, textbuf, buf);
			print_TextView ((GtkTextView*)textview, textbuf, "\%\n");
			
			/* ICMP */
			print_TextView ((GtkTextView*)textview, textbuf, "   ICMP protocol: ");
			snprintf(buf, BUF_SIZE, "%llu ", icmp_counter);
			print_TextView ((GtkTextView*)textview, textbuf, buf);
			print_TextView ((GtkTextView*)textview, textbuf, "Percentage: ");
			percentage = (icmp_counter * 100/ip_counter);
			snprintf(buf, BUF_SIZE, "%llu ", percentage);
			print_TextView ((GtkTextView*)textview, textbuf, buf);
			print_TextView ((GtkTextView*)textview, textbuf, "\%\n");
			
			/* Unknown IP */
			print_TextView ((GtkTextView*)textview, textbuf, "   Unknown: ");
			snprintf(buf, BUF_SIZE, "%llu ", unk_ip_counter);
			print_TextView ((GtkTextView*)textview, textbuf, buf);
			print_TextView ((GtkTextView*)textview, textbuf, "Percentage: ");
			percentage = (unk_ip_counter * 100/ip_counter);
			snprintf(buf, BUF_SIZE, "%llu ", percentage);
			print_TextView ((GtkTextView*)textview, textbuf, buf);
			print_TextView ((GtkTextView*)textview, textbuf, "\%\n");
		}
		else
		{
			snprintf(buf, BUF_SIZE, "No IP packets captured");
			print_TextView ((GtkTextView*)textview, textbuf, buf);
		}
	}
	else
	{
		snprintf(buf, BUF_SIZE, "No ethernet packets captured");
		print_TextView ((GtkTextView*)textview, textbuf, buf);
	}
	return 0;
}

/* counters to 0 */
void counters_to_zero(void)
{
	packet_counter = 0;
	ip_counter = 0;
	tcp_counter = 0;
	udp_counter = 0;
	arp_counter = 0;
	rarp_counter = 0;
	icmp_counter = 0;
	unk_ip_counter = 0;
	unk_eth_counter = 0;
}

unsigned long long  get_num_packets(void)
{
	return packet_counter;
}
