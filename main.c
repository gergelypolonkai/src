#include <stdio.h>
#include <string.h>
#include <krb5.h>
#include <time.h>
#include <stdlib.h>
#include <gtk/gtk.h>

#define HANDLE_KRB5_ERROR(x) if ( x ) \
{ \
	print_krb5_error( x, __FILE__, __LINE__ ); \
}

krb5_context gredentials_context;
krb5_ccache cred_cache;

void
print_krb5_error(krb5_error_code err_code, char *file, int line)
{
	const char *message;

	message = krb5_get_error_message(gredentials_context, err_code);
	fprintf(stderr, "CODE: %d, MSG: %s\nCalled from %s:%d\n", err_code, message, file, line);
	krb5_free_error_message(gredentials_context, message);
}

static GtkTreeModel *
create_and_fill_list(void)
{
	/* Kerberos-related variables */
	krb5_cc_cursor cursor;
	krb5_creds credential;

	GtkListStore *store;
	GtkTreeIter iter;

	store = gtk_list_store_new(4, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);

	HANDLE_KRB5_ERROR(krb5_cc_start_seq_get(gredentials_context, cred_cache, &cursor));

	while (krb5_cc_next_cred(gredentials_context, cred_cache, &cursor, &credential) == 0)
	{
		char *princ_name;
		char outstr[30];
		gchar *validity_start,
			 *validity_end,
			 *renew_until;
		struct tm *tmp;

		princ_name = NULL;

		gtk_list_store_append(store, &iter);

		tmp = localtime((const time_t *)&(credential.times.starttime));
		strftime((char *)&outstr, sizeof(outstr), "%m/%d/%y %H:%M:%S", tmp);
		validity_start = g_strdup((gchar *)&outstr);

		tmp = localtime((const time_t *)&(credential.times.endtime));
		strftime((char *)&outstr, sizeof(outstr), "%m/%d/%y %H:%M:%S", tmp);
		validity_end = g_strdup((gchar *)&outstr);

		tmp = localtime((const time_t *)&(credential.times.renew_till));
		strftime((char *)&outstr, sizeof(outstr), "%m/%d/%y %H:%M:%S", tmp);
		renew_until = g_strdup((gchar *)&outstr);

		HANDLE_KRB5_ERROR(krb5_unparse_name(gredentials_context, credential.server, &princ_name));

		gtk_list_store_set(store, &iter, 0, princ_name, 1, validity_start, 2, validity_end, 3, renew_until, -1);
	}

	HANDLE_KRB5_ERROR(krb5_cc_end_seq_get(gredentials_context, cred_cache, &cursor));

	krb5_free_context(gredentials_context);

	return GTK_TREE_MODEL(store);
}

static GtkWidget *
create_list(void)
{
	GtkCellRenderer *renderer;
	GtkTreeModel *model;
	GtkWidget *view;

	view = gtk_tree_view_new();

	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(view), -1, "Service principal", renderer, "text", 0, NULL);

	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(view), -1, "Validity starts", renderer, "text", 1, NULL);

	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(view), -1, "Validity ends", renderer, "text", 2, NULL);

	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(view), -1, "Renewable until", renderer, "text", 3, NULL);

	model = create_and_fill_list();

	gtk_tree_view_set_model(GTK_TREE_VIEW(view), model);

	g_object_unref(model);

	return view;
}

int
main(int argc, char **argv)
{
	/* GTK-related variables */
	GtkWidget *main_window;
	GtkWidget *ticket_list;

	char *main_princ_name;
	const char *default_cache;
	krb5_principal main_princ;

	gtk_init(&argc, &argv);

	HANDLE_KRB5_ERROR(krb5_init_context(&gredentials_context));

	default_cache = krb5_cc_default_name(gredentials_context);

	if (!default_cache || !*default_cache)
	{
		fprintf(stderr, "No default cache found. Please set KRB5CCNAME environment value accordingly.\n");
		return 1;
	}

	printf("Ticket cache: %s\n", default_cache);

	HANDLE_KRB5_ERROR(krb5_cc_resolve(gredentials_context, default_cache, &cred_cache));

	HANDLE_KRB5_ERROR(krb5_cc_get_principal(gredentials_context, cred_cache, &main_princ));

	main_princ_name = NULL;

	HANDLE_KRB5_ERROR(krb5_unparse_name(gredentials_context, main_princ, &main_princ_name));

	printf("Default principal: %s\n\n", main_princ_name);

	main_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	g_signal_connect(main_window, "delete_event", gtk_main_quit, NULL); /* TODO */

	ticket_list = create_list();

	gtk_container_add(GTK_CONTAINER(main_window), ticket_list);

	gtk_widget_show_all(main_window);

	gtk_main();

	return 0;
}

