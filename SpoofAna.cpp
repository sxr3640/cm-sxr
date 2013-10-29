#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <netdb.h>
#include <netinet/in_systm.h>
#include <net/route.h>
#include <stdlib.h>
#include <string>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <fstream>
#include <iostream>
#include "SpoofAna.h"
#include "RawSender.h"

using namespace std;

SpoofAna::SpoofAna() {
  sequence = 0;
  pid = getpid() & 0xffff;
  ipRef = "";
  ipRefPath = "";
}

SpoofAna::~SpoofAna() {
}

void SpoofAna::setIpRef(string ipApp) {
  ipRef = ipApp;
}

void SpoofAna::setIpRefPath(string pathApp) {
  ipRefPath = pathApp;
}

//retreive ipv6 of the interface from which i am launching tunneltrace
string SpoofAna::getOwnIp() {
  if (ipRef=="") {
    string app1 = ipRefPath + "tunneltrace.ip";
    ifstream inFile(app1.c_str());
    if (!inFile) {
      cerr << "unable to open input file, try creating the file '/etc/tunneltrace.ip' or use the -h option "<<endl;
      exit(1);
    }
    inFile >> ipRef;
    inFile.close();
  }
  int s = socket (AF_INET6, SOCK_DGRAM, 0);	/* open raw socket */
  struct sockaddr_in6 sin;
  struct sockaddr_in6 sin2;
  socklen_t len;
  bzero(&sin,sizeof(sin));
  int res = inet_pton(AF_INET6,ipRef.c_str(),&sin.sin6_addr);
  if (res==0) {
    printf("error with ip given as ipv6 of reference, either inserted bad with the -h, or in the /etc/tunneltrace.ip file\n");
    exit(1);
  }
  sin.sin6_port=htons(1025);
  sin.sin6_family=AF_INET6;
  len = sizeof(sin2);
  if (connect(s,(struct sockaddr*)&sin,sizeof(sin))==0) {
    getsockname(s,(struct sockaddr*)&sin2,&len);
    char abuf[INET6_ADDRSTRLEN];
    (void) inet_ntop(AF_INET6, &sin2.sin6_addr , abuf , sizeof(abuf));
    string apps = abuf;
    return apps;
  }
  else {
    return "";//printf("errno is %d\n",errno);
    close(s);
  }
}

//this function generaters checksum ipv6
unsigned short SpoofAna::in_cksum(unsigned short *ptr, int nbytes)
{
        register long   sum;
        u_short         oddbyte;
        register        u_short answer;

        sum = 0;
        while (nbytes > 1) {
                sum += *ptr++;
                nbytes -= 2;
        }

        if (nbytes == 1) {
                oddbyte = 0;
                *((u_char *) & oddbyte) = *(u_char *) ptr;
                sum += oddbyte;
        }

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        answer = ~sum;
        return (answer);
}


unsigned short		/* this function generates header checksums ipv4*/
SpoofAna::csum (unsigned short *buf, int nwords)
{
  unsigned long sum;
  for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}


u_short SpoofAna::pseudo_check(struct in6_addr from, struct in6_addr to, void *pkt, int length, int nh)
{
    struct pseudo6 {
        struct in6_addr src;
        struct in6_addr dst;

        unsigned short plen;
        u_char zero;
        u_char nh;
    } *psd;

    char *tosum;
    u_short resultz;

    tosum = (char *)(malloc(length + sizeof(struct pseudo6)));
    memset(tosum, 0, length + sizeof(struct pseudo6));
    psd = (struct pseudo6 *)(tosum);
    memcpy(tosum + sizeof(struct pseudo6), pkt, length);
    psd->src = from;
    psd->dst = to;
    psd->plen = htons(length);
    psd->nh = nh;
    resultz = in_cksum((u_short *)tosum, length + sizeof(struct pseudo6));
    free(tosum);
    return(resultz);
}
    //returns value of the socket opened for the Receiver, otherwise returns -1 (error)
    //options : 0 = injected ping, 1 = DyingPacket, 2 = PingPongPacket, 3 = FragmentedInjectedPing
int SpoofAna::Sender(string ipv6In, string ipv6Out, string ipv4In, string ipv4Out, int options) {
      RawSender s1;
      int recvfd = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
      if(recvfd < 0) {
        perror("socket");
        close(recvfd);
        return -1;
      }

      char datagram[4096];	/* this buffer will contain ip header, ipv6 header, icmpv6 header
                               and payload. we'll point an ip header structure
                               at its beginning, ipv6 header structure and icmpv6 header structure after
                               that to write the header values into it */
      char icmp6PL[8];
      struct ip *iph = (struct ip *) datagram;

      memset (datagram, 0, 4096);	/* zero out the buffer */
    /* we'll now fill in the ip header values, see above for explanations */
      iph->ip_hl = 5;
      iph->ip_v = 4;
      iph->ip_tos = 0;
      if (options == 3) iph->ip_len = 118; //let's say 3 fragments (of 68bytes each) :)
      else iph->ip_len = 68;
      iph->ip_id = 12756;	/* the value doesn't matter here */
      iph->ip_off = 0;
      iph->ip_ttl = 255;
      iph->ip_p = 41; //6 - tcp, 1 - icmp
      iph->ip_sum = 0;		/* set it to 0 before computing the actual checksum later */
      iph->ip_src.s_addr = inet_addr (ipv4In.c_str());
      iph->ip_dst.s_addr = inet_addr (ipv4Out.c_str());
      iph->ip_sum = csum ((unsigned short *) datagram, (iph->ip_hl*2) >> 1);

      struct ip6_hdr *ip6 = (struct ip6_hdr *) (datagram +  sizeof(struct ip));

      in6_addr in;
      in6_addr *p_in=&in;
      int res=inet_pton(AF_INET6, ipv6In.c_str() , p_in);

      in6_addr in2;
      in6_addr *p_in2=&in2;
      int res2=inet_pton(AF_INET6, ipv6Out.c_str() , p_in2);

      uint32_t pippo;
      pippo = 6<<28 |0 << 8|0;
      ip6->ip6_flow = htonl(pippo); //for setting version = 6
      ip6->ip6_plen = htons(8);
      ip6->ip6_nxt = 58; //58 = IPPROTO_ICMP6
      switch(options) {
        case (0) :
          ip6->ip6_hlim = 64; //injected ping
          break;
        case (1) :
          ip6->ip6_hlim = 1; //dying packet
          break;
        case (2) :
          ip6->ip6_hlim = 2; //ping-pong packet
          break;
        case (3) :
          ip6->ip6_hlim = 64; //fragmented injected ping
          break;
      }

      ip6->ip6_src = in;
      ip6->ip6_dst = in2;

      struct icmp6_hdr *icmp;
      icmp = (struct icmp6_hdr *) (datagram + sizeof(struct ip) + sizeof(struct ip6_hdr));
      icmp->icmp6_type = 128;
      icmp->icmp6_code = 0;
      icmp->icmp6_cksum = 0;
      icmp->icmp6_id =pid;
      icmp->icmp6_seq=sequence;
      memset(&icmp6PL, 0, sizeof(icmp6PL));

      struct icmp6_hdr *icmp2;
      icmp2 = (struct icmp6_hdr *) icmp6PL;
      icmp2->icmp6_type = icmp->icmp6_type;
      icmp2->icmp6_code = icmp->icmp6_code;
      icmp2->icmp6_cksum = 0;
      icmp2->icmp6_id=icmp->icmp6_id;
      icmp2->icmp6_seq=icmp->icmp6_seq;

      icmp->icmp6_cksum = pseudo_check(ip6->ip6_src,ip6->ip6_dst, &icmp6PL, sizeof(icmp6PL), 58);

      //input to sender
   /*   for(int i=0; i<iph->ip_len; i++) {
         printf("%02x ", (int)*(datagram + i));
         if (!((i+1)%16)) printf("\n");
    };
    printf("\n");
*/

      //To call the RawSender, fragmentation and sending module, where I give in the
      //whole packet and the size of each fragment, that has to be multiple of 8
      if (s1.SendPacket(datagram,68)==-1) return -1;

      return recvfd;

    }

//options : 0 = injected ping, 1 = DyingPacket, 2 = PingPongPacket
string SpoofAna::Receiver(int options,int recvfd) {
  int ret=0;
  uint8_t *ado_buffer;
  char *my_buffer;
  struct icmp6_filter filter;
  //int recvfd;
  struct msghdr msg;
  struct iovec iov;
  int found = 0;
  struct in6_pktinfo info;
  struct cmsghdr *cm;
  struct in6_addr destination_address;
  struct sockaddr_storage ss;
  struct sockaddr_in6 *sender_address;

  ado_buffer = (uint8_t *)malloc(ADO_BUF_SIZE);
  if (ado_buffer == NULL) return "";

  my_buffer = (char *)malloc(BUFFER_LENGTH);
  if (my_buffer == NULL) return "";

  //qui setti correttamente il buffer di destinazione
  iov.iov_base = my_buffer;
  iov.iov_len = BUFFER_LENGTH;

  memset(&msg, 0, sizeof(msg));

  msg.msg_name= &ss;
  msg.msg_namelen=sizeof(ss);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = ado_buffer;
  msg.msg_controllen = ADO_BUF_SIZE;

 // recvfd = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
//printf("socket recvfd in receiver : %i \n",recvfd);


  if(recvfd < 0) {
    perror("socket");
    close(recvfd);
    return "";
  }
/*  ICMP6_FILTER_SETBLOCKALL(&filter);
  ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);//INJECTED PING
  ICMP6_FILTER_SETPASS(3,&filter); // DYING PACKET
 // ICMP6_FILTER_SETPASS(1,&filter);


  if (setsockopt(recvfd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter)) < 0) {
    perror("setsockopt ICMP6_FILTER");
    close(recvfd);
    return "";
  }
*/
  int on=1;
  setsockopt(recvfd, IPPROTO_IPV6, IPV6_PKTINFO, &on, sizeof(on));

  fd_set fds;
  struct timeval time1, time2, tv = {6,0};

  FD_ZERO(&fds);
  FD_SET(recvfd, &fds);

  gettimeofday(&time1, NULL);
  while(select(recvfd+1, &fds, NULL, NULL, &tv) != 0) {
    /* Update timeout */
    gettimeofday(&time2, NULL);
    /* Check for carry, or we'll be sleeping forever... */
    if(time2.tv_usec < time1.tv_usec) {
        time2.tv_sec = time2.tv_sec - 1;
        time2.tv_usec = time2.tv_usec + 1000000L;
    }
    tv.tv_sec = time2.tv_sec - time1.tv_sec;
    tv.tv_usec = time2.tv_usec - time1.tv_usec;
    time1 = time2;

    /* Paranoia helps sometimes. If 0s timeout, select will wait forever. */
    if(tv.tv_sec == 0 && tv.tv_usec == 0) {
        tv.tv_sec = 0;
        tv.tv_usec = 100000L;
    }
   ret=recvmsg(recvfd,&msg,0);
   //controllo che non ci siano stati errori..
   if (ret < 0) {
     close(recvfd);
     return "";
   }
  if (ret!=0) {
    for (cm = CMSG_FIRSTHDR(&msg); cm!= NULL; cm= CMSG_NXTHDR(&msg, cm)) {
      if (cm->cmsg_level == IPPROTO_IPV6 &&
          cm->cmsg_type == IPV6_PKTINFO &&
          cm->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo))) {
               info = *(struct in6_pktinfo*) CMSG_DATA(cm);
               found = 1;
               break;
      }
     }

    destination_address = info.ipi6_addr;

    struct icmp6_hdr *icmp6;
      switch(options) {
        case (0) :
          icmp6= (struct icmp6_hdr* ) my_buffer; //injected ping
          if (icmp6->icmp6_type==129) {
            if ((icmp6->icmp6_id==pid) && (icmp6->icmp6_seq==sequence)) {
              close(recvfd);
              return "ok"; //injected ping worked
            }
          }
          break;
        case (1) :
          icmp6= (struct icmp6_hdr* ) (my_buffer + sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr)); //dying packet
          if (icmp6->icmp6_type==128) {
            if ((icmp6->icmp6_id==pid) && (icmp6->icmp6_seq==sequence)) {
              char abuf[INET6_ADDRSTRLEN];
              sender_address = (struct sockaddr_in6 *)&ss;
              (void) inet_ntop(AF_INET6, &sender_address->sin6_addr , abuf , sizeof(abuf));
              close(recvfd);
              string sapp = abuf;
              return sapp; //let's return the dying packet, source address
            }
          }
          break;
        case (2) : //ping-pong packet
          icmp6= (struct icmp6_hdr* ) my_buffer; //injected ping

          if ((icmp6->icmp6_type==3)||(icmp6->icmp6_type==129)) {
            if ((icmp6->icmp6_id==pid) && (icmp6->icmp6_seq==sequence)) {
              close(recvfd);
              return "ok"; //ping-pong worked
            }
            else {
              icmp6= (struct icmp6_hdr* ) (my_buffer + sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr)); //dying packet
              if ((icmp6->icmp6_id==pid) && (icmp6->icmp6_seq==sequence)) {
                char abuf[INET6_ADDRSTRLEN];
                sender_address = (struct sockaddr_in6 *)&ss;
                (void) inet_ntop(AF_INET6, &sender_address->sin6_addr , abuf , sizeof(abuf));
                close(recvfd);
                string sapp = abuf;
                return sapp; //let's return the ping-pong packet, source address
              }
            }
          }
         break;
      }



    }

   /* char abuf[INET6_ADDRSTRLEN];
    (void) inet_ntop(AF_INET6, &destination_address , abuf , sizeof(abuf));
    printf("indirizzo destinazione: %s \n",abuf);
*/

  }
  close(recvfd);
  return "";
}

//1 - Injected Ping successfull, 0 - error
// ipv6Out - interface that we are trying to ping, ipv4in - ipv4out = tunnelendpoint, ipv6In - our interface
int SpoofAna::InjectedPing(string ipv6In, string ipv4In, string ipv4Out) {
  sequence ++;
  if (Receiver(0,Sender(ipv6In,ipRef,ipv4In,ipv4Out,0))=="ok") return 1;
  else return 0;
  //int pid_a;
  /* get cHild process */
 /* if ((pid_a = fork()) < 0) {
    perror("fork");
    exit(1);
  }*/
 // if (pid_a == 0) { /* child */
   /* sleep(2);
    if (Sender(ipv6In, ipv6Out, ipv4In, ipv4Out, 0)!=0) {
      exit(0);
    }
    else exit(1);
  }*/
  //else /* parent */ {  /* pid hold id of child */
   /* if (Receiver(0)=="ok") {
      kill(pid_a,SIGKILL);
      return 1;
    }
    else {
      kill(pid_a,SIGKILL);
      return 0;
    } */
  //}
}

// returns the ipv6Out given by the time exceed message
string SpoofAna::DyingPacket(string ipv6In, string ipv4In, string ipv4Out) {
  sequence ++;
  return Receiver(1,Sender(ipv6In,ipRef,ipv4In,ipv4Out,1));
  //int pid_a;
  /* get child process */
  /*if ((pid_a = fork()) < 0) {
    perror("fork");
    exit(1);
  }
  if (pid_a == 0) {  */ /* child */
    /*sleep(2);
    if (Sender(ipv6In, "2001:760::4:1:4", ipv4In, ipv4Out, 1)!=0) {
      exit(0);
    }
    else exit(1);
  }
  else */ /* parent */ /*{   pid hold id of child */
    /*string s=Receiver(1);
    kill(pid_a,SIGKILL);
    return s;
  }
}*/
}

//ping pong packet
string SpoofAna::PingPongPacket(string ipv6In, string ipv6Out, string ipv4In, string ipv4Out) {
  sequence ++;
  return Receiver(2,Sender(ipv6In,ipv6Out,ipv4In,ipv4Out,2));
   // int pid_a;
  /* get child process */
 /* if ((pid_a = fork()) < 0) {
    perror("fork");
    exit(1);
  }
  if (pid_a == 0) {*/ /* child */
  /*  sleep(2);
    if (Sender(ipv6In, ipv6Out, ipv4In, ipv4Out, 2)!=0) {
      exit(0);
    }
    else exit(1);
  }
  else*/ /* parent */ /*{   pid hold id of child */
 /*   string s=Receiver(2);
    kill(pid_a,SIGKILL);
    return s;
  }
}
*/
}

int SpoofAna::FragmentedInjectedPing(string ipv6In, string ipv4In, string ipv4Out) {
  sequence ++;
  if (Receiver(0,Sender(ipv6In,ipRef,ipv4In,ipv4Out,3))=="ok") return 1;
  else return 0;
}
//Ping Pong with pingable interface
//string SpoofAna::PingPongPacket(string ipv6In, string ipv4In, string ipv4Out) {
 // sequence ++;
  //int pid_a;
 // return Receiver(2,Sender(ipv6In,ipRef,ipv4In,ipv4Out,2));
  /* get child process */
 /* if ((pid_a = fork()) < 0) {
    perror("fork");
    exit(1);
  }
  if (pid_a == 0) { */ /* child */
/*    sleep(2);
    if (Sender(ipv6In, "2001:760::4:1:4", ipv4In, ipv4Out, 2)!=0) {
      exit(0);
    }
    else exit(1);
  }
  else*/ /* parent */ /*{  pid hold id of child */
 /*   string s=Receiver(2);
    kill(pid_a,SIGKILL);
    return s;
  }
}*/
//}
