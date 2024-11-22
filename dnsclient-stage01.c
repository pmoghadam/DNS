/* DNS client implementation according to RFC1035
Copyright (C) 2024  Pejman Moghadam

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, see <https://www.gnu.org/licenses/>.
*/

/* https://www.rfc-editor.org/rfc/rfc1035.txt */

// gcc dnsclient-stage01.c -o dnsclient-stage01

#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>

/*

2.3.4. Size limits

UDP messages    512 octets or less

*/
#define MAXMSGLEN 512

/*

4. MESSAGES

4.1. Format

    +---------------------+
    |        Header       |
    +---------------------+
    |       Question      | the question for the name server
    +---------------------+
    |        Answer       | RRs answering the question
    +---------------------+
    |      Authority      | RRs pointing toward an authority
    +---------------------+
    |      Additional     | RRs holding additional information
    +---------------------+

4.1.1. Header section format

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

*/
typedef struct {
    uint16_t id;        // A 16 bit identifier assigned by client

    // Little-endian
    uint16_t rd:1;      // Recursion Desired
    uint16_t tc:1;      // TrunCation
    uint16_t aa:1;      // Authoritative Answer
    uint16_t opcode:4;  // kind of query
    uint16_t qr:1;      // query (0) or response (1)

    // Little-endian
    uint16_t rcode:4;   // Response code
    uint16_t z:3;       // Reserved
    uint16_t ra:1;      // Recursion Available

    uint16_t qdcount;   // number of entries in the question section
    uint16_t ancount;   // number of entries in the answer section
    uint16_t nscount;   // number of NS RRs in the authority section
    uint16_t arcount;   // number of RRs in the additional section
} DNS_HEADER;

/*

4.1.2. Question section format

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

*/
// Constant size fields of question section
typedef struct {
        uint16_t qtype;
        uint16_t qclass;
} DNS_QUESTION;

/*

QNAME           a domain name represented as a sequence of labels, where
                each label consists of a length octet followed by that
                number of octets.  The domain name terminates with the
                zero length octet for the null label of the root.  Note
                that this field may be an odd number of octets; no
                padding is used.
*/
int convert_qname(char *buf, char *name)
{
    int i;
    char *count = buf;

    *count = 0;
    for(i = 0; i < strlen(name); i++) {
        if(name[i] != '.') {
            buf[i+1] = name[i];
            (*count)++;
        } else {
            count = &buf[i+1];
            *count = 0;
        }
    }
    buf[i+1] = 0;

    return i+2;
}

void show_packet(unsigned char *buf, int len)
{
    int i, j;
    char str[17];

    str[16] = 0;
    printf("\n");
    for (i = 0; i < len; i += 16) {
        fprintf(stdout, "   ");
        for (j = 0; j < 16 && i + j < len; j++) {
            fprintf(stdout, "%02x ", buf[i + j]);

            if (buf[i + j] > 32 && buf[i + j] < 127)
                str[j] = buf[i + j];
            else
                str[j] = '.';
        }
        for (; j < 16; j++) {
            fprintf(stdout, "   ", buf[i + j]);
            str[j] = ' ';
        }
        printf("   |   %s   |\n", str);
    }
    fflush(stdout);
}

int create_query_packet(char *pkt, char *name)
{
    puts("Creating Query Packet ...");

    char *pkt_p = pkt;
    DNS_HEADER *header = (DNS_HEADER *)pkt_p;

    header->id = (unsigned short) htons(getpid());
    header->qr = 0;             // Query
    header->opcode = 0;         // Standard query
    header->aa = 0;             // Non-authoritative
    header->tc = 0;             // Not truncated
    header->rd = 1;             // Recursion desired
    header->ra = 0;             // Recursion not available
    header->z = 0;              // Reserved
    header->rcode = 0;          // Response code
    header->qdcount = htons(1); // we have only 1 question
    header->ancount = 0;        // Answer count
    header->nscount = 0;        // NS count
    header->arcount = 0;        // Additional records count
    pkt_p += sizeof(DNS_HEADER);

    pkt_p += convert_qname(pkt_p, name);

    DNS_QUESTION *question = (DNS_QUESTION *)pkt_p;
    question->qtype = htons(1);     // Address Record
    question->qclass = htons(1);    // Internet class
    pkt_p += sizeof(DNS_QUESTION);

    return pkt_p - pkt;
}

// Send Query and Receive Response
ssize_t sndqr_rcvrs(char *packet, int len, char *server)
{
    puts("Opening socket ...");
    int sockfd = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP);

    puts("Sending Query ...");

    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_port = htons(53);
    dst.sin_addr.s_addr = inet_addr(server);

    sendto(sockfd, packet, len, 0,
            (struct sockaddr*)&dst, sizeof(dst));

    puts("Receiving Response ...");

    socklen_t addrlen = sizeof(dst);
    ssize_t recvlen = recvfrom(sockfd, packet, MAXMSGLEN, 0,
            (struct sockaddr*)&dst, &addrlen);

    puts("Closing socket ...");
    close(sockfd);

    return recvlen;
}

int main()
{
    char *name = "mail.yahoo.com";
    char *server = "8.8.4.4";

    char packet[MAXMSGLEN];
    int len;

    printf("Resolving: %s\n", name);
    printf("Server: %s\n", server);

    len = create_query_packet(packet, name);
    printf("Length: %d\n", len);
    show_packet(packet, len);
    printf("\n");

    len = sndqr_rcvrs(packet, len, server);
    printf("Length: %d\n", len);
    show_packet(packet, len);
    printf("\n");

    return 0;
}
