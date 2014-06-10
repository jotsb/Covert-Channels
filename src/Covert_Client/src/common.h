/*
 * common.h
 *
 *  Created on: Apr 20, 2014
 *  Author: Jivanjot S. Brar
 */

#ifndef COMMON_H_
#define COMMON_H_

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>

// Globals
char *options[] = { "-dest", "-dest_port", "-source", "-src_port", "-file",
		"-urg_ptr", "-seq", "-ack", "-id", "-tos", "-frag_off" };

typedef struct _client client;
//typedef struct _packets packets;

struct _client {
	unsigned int source_host;
	unsigned int dest_host;
	unsigned short source_port;
	unsigned short dest_port;
	char filename[80];
	char srchost[80];
	char desthost[80];
	int urg_ptr;
	int seq;
	int ack;
	int id;
	int tos;
	int frag_off;
	int file;
	int dest;
	int destport;
	int source;
	int src_port;
};

static struct _packets {
	struct iphdr ip;
	struct tcphdr tcp;
} packets;

static struct _pseudo_header {
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	struct tcphdr tcp;
} pseudo_header;

void print_usage(char *argv[]);
client *client_new(void);
void packet_new(client *, int ch);
void validate_args(int argc, char *argv[], client *c);
bool if_exists(char *array[], char *value);
void SystemFatal(char *c);
unsigned int host_convert(char *hostname);
unsigned short in_cksum(unsigned short *addr, int len);
void send_packets(client *);

#endif /* COMMON_H_ */
