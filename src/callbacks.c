/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*- */
/*
 * callbacks.c
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

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

//#include <gtk/gtk.h>
//#include <glade/glade.h>
//#include <string.h>
//#include <stdlib.h>
//#include <pcap.h>

#include "callbacks.h"

void on_window_destroy (GtkObject *object, gpointer user_data)
{
	stop_loop();
	kill_pcap();
    gtk_main_quit();
}

void button_start_click (GtkWidget *widget, gpointer window)
{
	gchar *str;
	int ret;
	
	/* default parameters */
	struct st_parameters parameters = {
		DEF_ARGUMENTS,
		DEF_INTERFACE,
		DEF_FILTER,
		DEF_NUMPACKETS};
	
	struct st_parameters *ptr_parameters;
	ptr_parameters = &parameters;
	
	parameters.arguments = DEF_ARGUMENTS;
	strcpy(parameters.interface, DEF_INTERFACE);
	strcpy(parameters.filter, DEF_FILTER);
	strcpy(parameters.numPackets, DEF_NUMPACKETS);

	return_to_zero();
	activate_deactivate();
	if (f_pass_parameters (ptr_parameters) == 0)
	{
		if ((strcmp(parameters.numPackets, "-1")) != 0)
		{
			str = g_strdup_printf("Initializing capture. IF: %s Num pkts: %d",parameters.interface,atoi(parameters.numPackets));
		}else{
			str = g_strdup_printf("Initializing capture. IF: %s Num pkts: Not defined",parameters.interface);
		}
		gtk_statusbar_push(GTK_STATUSBAR(window),
        gtk_statusbar_get_context_id(GTK_STATUSBAR(window), str), str);
		g_free(str);
		if((ret = loop_capture (parameters.arguments,
					   parameters.interface,
					   parameters.filter,
					   parameters.numPackets)) == 1)
		{
			gest_err_msg ("Could not initiate capture loop");
		}else{
			if ((strcmp(parameters.numPackets, "-1")) != 0)
			{
				str = g_strdup_printf("Finished. %d Packets captured FOFO on interface %s.",atoi(parameters.numPackets),parameters.interface);
				activate_deactivate ();
			}else{
				activate_deactivate ();
			}
			str = g_strdup_printf("Finished. %llu Packets captured on interface %s.",get_num_packets (),parameters.interface);
		}
			gtk_statusbar_push(GTK_STATUSBAR(window),
        	gtk_statusbar_get_context_id(GTK_STATUSBAR(window), str), str);
			g_free(str);
	}
}

void button_finish_click (GtkWidget *widget, gpointer window)
{
	stop_loop();
}

void on_menu_save_activate (void)
{
	gchar *str;

	if ((str = which_file()) == NULL)
	{
		gest_err_msg ("Log not saved");
	}else{
	write_file(str);
	}
	g_free(str);
}

void on_menu_quit_activate(void){
	stop_loop();
	kill_pcap();
	gtk_main_quit();
}

gint delete_event( GtkWidget *widget,
                   GdkEvent  *event,
                   gpointer   data )
{
    return(FALSE);
}

/* Menu "About" */
void on_menu_about_activate (GtkWidget *window)
{
        static const gchar * const authors[] = {
		"Ricard Pradell <mombars@users.berlios.de>",
		NULL
	};

	static const gchar copyright[] = \
		"Copyright \xc2\xa9 2010 Ricard Pradell";

	static const gchar comments[] = "Dumbado: graphic network packets analyzer";

	gtk_show_about_dialog (GTK_WINDOW (window),
			       "authors", authors,
			       "comments", comments,
			       "copyright", copyright,
			       "version", "0.3",
			       "website", "http://dumbado.wordpress.com",
			       "program-name", "PFM UOC Dumbado",
			       "logo-icon-name", GTK_STOCK_DELETE,
			       NULL); 
}
