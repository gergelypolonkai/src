all:
	gcc -o gredentials `krb5-config --cflags --libs krb5` `pkg-config --cflags --libs gtk+-2.0` -Wall -g -O2 main.c

