#include <netdb.h>
#include <netinet/in_systm.h>
#include <net/route.h>
#include <stdlib.h>
#include <string>
#include <stdio.h>
#include <iostream>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include "RawSender.h"
#include <cstring>
using namespace std;

RawSender::RawSender() {
}

RawSender::~RawSender() {
}

unsigned short		/* this function generates header checksums ipv4*/
RawSender::csum (unsigned short *buf, int nwords)
{
  unsigned long sum;
  for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}

//module for Sending/Fragmenting Raw Socket IPv4 Packets,
//if the packetSize is smaller than the packet contained in the packet variable, then
//SendPacket fragments the packet into as many packets with the size of packetSize as many needed
//for sending the whole packet
//SendPacket = 0 -> Success
//SendPacket = -1 -> Fail
//maximum Packet size to fragment = 4096
int RawSender::SendPacket(char packet[4096],int packetSize) {
  if ((packetSize > 68)||(((packetSize-20)%8)!=0)) return -1; // SendPacket Failure, because packetSize > minimum MTU IPv4
                                                              // the payloadSize has to be multiple of 8 for fragmenting
  else {
    int s = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);	/* open raw socket */
    if(s < 0) {
      perror("socket");
      close(s);
      return -1;
    }
    {				/* lets do it the ugly way.. */
      int one = 1;
      const int *val = &one;
      if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
        printf ("Warning: Cannot set HDRINCL!\n");
    }

    char datagram[4096];

    memcpy(datagram,packet,packetSize);


    struct ip *iph = (struct ip *) datagram;
    struct sockaddr_in sin;
                          /* the sockaddr_in containing the dest. address is used
                             in sendto() to determine the datagrams path */

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = iph->ip_dst.s_addr;
/*
    for(int i=0; i<packetSize; i++) {
         printf("%02x ", (int)*(datagram + i));
         if (!((i+1)%16)) printf("\n");
    };
    printf("\n");

    cout<<iph->ip_len<<endl;
*/
    if (iph->ip_len <= packetSize) { //Fragmenting is not necessary
//      cout<<"il pacchetto è più piccolo della grandezza massima"<<endl;
      if (sendto (s,		/* our socket */
            datagram,	/* the buffer containing headers and data */
            packetSize,	/* total length of our datagram */
            0,		/* routing flags, normally always 0 */
            (struct sockaddr *) &sin,	/* socket addr, just like in */
            sizeof (sin)) < 0)		/* a normal send() */
        { close(s);
          return -1;}
    }
    else {
  //    cout<<"Frammentiamo..."<<endl;
      int plength = iph->ip_len - 20;
      int pPacketSize = packetSize - 20;
      int fragments = plength / pPacketSize;  //to calculate fragments..
      if ((plength%pPacketSize)!=0) fragments ++;
//      cout<<"fragments :"<<fragments<<endl;

      int offset = 0;

      iph->ip_len = packetSize;
      //Fragmentation starts... , a packet for each fragment is calculated and sent...
      for (int i=0; i<fragments; i++) {
    //    cout<<"frammento :"<<(i+1)<<endl;

        iph->ip_off = 0;
        iph->ip_off = htons(IP_MF + offset);

        if (i==(fragments-1)) {
          iph->ip_off = htons(offset);
          packetSize = (plength - (pPacketSize*i)) + 20;
          iph->ip_len = packetSize;
        }

     //   cout<<iph->ip_len<<endl;

        iph->ip_sum = 0;
        iph->ip_sum = csum ((unsigned short *) datagram, (iph->ip_hl*2) >> 1);

        memcpy(datagram+20 ,packet+20+(pPacketSize*i) , packetSize);

   /*     for(int i=0; i<packetSize; i++) {
          printf("%02x ", (int)*(datagram + i));
          if (!((i+1)%16)) printf("\n");
        };
        printf("\n");
*/

        if (sendto (s,		/* our socket */
                  datagram,	/* the buffer containing headers and data */
                  packetSize,	/* total length of our datagram */
                  0,		/* routing flags, normally always 0 */
                  (struct sockaddr *) &sin,	/* socket addr, just like in */
                  sizeof (sin)) < 0)		/* a normal send() */
           { close(s);
             return -1;}
        offset = offset + (pPacketSize/8);
      }
    }
    close (s);
    return 0;
  }
}
