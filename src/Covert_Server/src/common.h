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
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>

// Globals
char *options[] = { "-listen_port", "-source", "-bounce", "-ofile", "-urg_ptr", "-seq",
		"-ack", "-id", "-tos", "-frag_off" };

typedef struct _client client;
//typedef struct _packets packets;

struct _client {
	unsigned int source_host;
	unsigned short dest_port;
	char filename[80];
	char srchost[80];
	int bounce;
	int urg_ptr;
	int seq;
	int ack;
	int id;
	int tos;
	int frag_off;
	int file;
	int destport;
	int source;
};

static struct _packets {
	struct iphdr ip;
	struct tcphdr tcp;
} recv_pkt;

void print_usage(char *argv[]);
client *client_new(void);
void validate_args(int argc, char *argv[], client *c);
unsigned int host_convert(char *hostname);
bool if_exists(char *array[], char *value);
void SystemFatal(char *c);
void recv_packets(client *);

#endif /* COMMON_H_ */
