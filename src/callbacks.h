/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*- */
/*
 * callbacks.h
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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <config.h>
#include <gtk/gtk.h>
#include <glade/glade.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <net/ethernet.h>
#include <netinet/ether.h> 
#include <netinet/ip.h>
#include <ctype.h>


/* default parameters */
#define DEF_ARGUMENTS 3
#define DEF_INTERFACE "any"
#define DEF_FILTER ""
#define DEF_NUMPACKETS "-1"

/* char* limit of parameters */
#define MAX_INTERFACE 10 
#define MAX_FILTER 1000
#define MAX_NUMPACKETS 100

/* Glade XML */
#define GLADE_FILE "/usr/local/bin/dumbado.glade"

/* pass parameters struct*/
struct st_parameters{
	int arguments;
	char interface[MAX_INTERFACE];
	char filter[MAX_FILTER];
	char numPackets[MAX_NUMPACKETS];
};

/* capture loop */
int loop_capture (int argc, char *interface, char *filter, char *num_packets);

/* error and messages management */
void gest_err_msg (const char *msg);

/* shows a dialog to save a file, returns file name */
gchar *which_file(void);

/* we've got a file name, and want to save textview's content */
void write_file(gchar *file_name);

void stop_loop(void);
void return_to_zero(void);
void activate_deactivate(void);
int f_pass_parameters(struct st_parameters *parameters);
void kill_pcap(void);
unsigned long long  get_num_packets(void);
void button_start_click(GtkWidget *widget, gpointer window);
void button_finish_click(GtkWidget *widget, gpointer window);
void on_menu_save_activate(void);
void on_menu_quit_activate(void);
void on_menu_about_activate (GtkWidget *window);
gint delete_event( GtkWidget *widget,
                   GdkEvent  *event,
                   gpointer   data );
void on_window_destroy (GtkObject *object, gpointer user_data);
