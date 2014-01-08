#include <iostream>
#include <stdlib.h>
#include <string>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <netdb.h>
#include <netinet/in_systm.h>
#include <net/route.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "Segment.h"
#include "SegmentAna.h"
#include "Analyzer.h"
#include "IfAna.h"
#include "NameIpAna.h"
#include "RawSender.h"

using namespace std;

const size_t BUFFER_LENGTH = 65536;
const size_t ADO_BUF_SIZE = 1024;

int sequence = 0;
int relsequence = 0; //to apply when using fragmented traceroute6
int relsequenceapp = 0; //for backing up fragmented tr..
int pid = getpid() & 0xffff;
unsigned int mtu = 0;
unsigned int appmtu = 0;
string vp4source = "";
string vp4dest = "";
string vp4sourceapp = "";
string vp4destapp = "";

Analyzer::Analyzer() {
  ipRef = "";
  ipRefPath = "";
  option = "";
}

//this function generaters checksum ipv6
unsigned short Analyzer::in_cksum(unsigned short *ptr, int nbytes)
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
Analyzer::csum (unsigned short *buf, int nwords)
{
  unsigned long sum;
  for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}


u_short Analyzer::pseudo_check(struct in6_addr from, struct in6_addr to, void *pkt, int length, int nh)
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


string Analyzer::getOwnIp(string ipRef) {
  int s = socket (AF_INET6, SOCK_DGRAM, 0);	/* open raw socket */
  struct sockaddr_in6 sin;
  struct sockaddr_in6 sin2;
  socklen_t len;
  bzero(&sin,sizeof(sin));
  int res = inet_pton(AF_INET6,ipRef.c_str(),&sin.sin6_addr);
  if (res==0) {
    printf("error with ip given as ipv6 of reference, either inserted bad with the -h, or in the tunneltrace.ip file\n");
    exit(1);
  }
  sin.sin6_port=htons(1025);
  sin.sin6_family=AF_INET6;
  len = sizeof(sin2);

  socklen_t optlen = sizeof(unsigned int);

  int discover = 0;

  if (setsockopt(s, IPPROTO_IPV6, IPV6_MTU_DISCOVER,
   (char*) &discover, sizeof(discover)) == -1) perror("setsockopt IPV6_MTU_DISCOVER");
  if (connect(s,(struct sockaddr*)&sin,sizeof(sin))==0) {
    //let's set the mtu of our connection for future mtu path discovery
//    getsockopt(s, IPPROTO_IPV6, IPV6_MTU, &mtuinfo, &infolen);
   // cout<<"mtu: "<<mtu<<endl;
   if (mtu == 0) { //I look for the MTU only the first time OwnIp is called
     if (getsockopt(s, IPPROTO_IPV6, IPV6_MTU, (void *) &mtu, &optlen) < 0) {
         printf("error determinig MTU\n");
         close(s);
         exit(2);
     }
  //   cout<<mtu<<endl;
   }
    //now we can look for our own ipv6 address
    getsockname(s,(struct sockaddr*)&sin2,&len);
    char abuf[INET6_ADDRSTRLEN];
    (void) inet_ntop(AF_INET6, &sin2.sin6_addr , abuf , sizeof(abuf));
    string apps = abuf;
    close(s);
    return apps;
  }
  else {
    printf("error on connect, when determinig ownIP!!!\n");
    close(s);
    exit(2);
  }

}

string Analyzer::Receiver(int recvfd) {
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


  if(recvfd < 0) {
    perror("socket");
    close(recvfd);
    return "";
  }

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
    icmp6= (struct icmp6_hdr* ) my_buffer;
    switch(icmp6->icmp6_type) {
      case (129) : {
        if ((icmp6->icmp6_id==pid) && (icmp6->icmp6_seq==sequence)) {
          close(recvfd);
          return "ok"; //echo reply, traceroute6 stops
        }
      }
      break;
      case (3) : {
        struct icmp6_hdr *icmp6_2;
        icmp6_2= (struct icmp6_hdr* ) (my_buffer + sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr));
        if ((icmp6_2->icmp6_id==pid) && (icmp6_2->icmp6_seq==sequence)) {
          char abuf[INET6_ADDRSTRLEN];
          sender_address = (struct sockaddr_in6 *)&ss;
          (void) inet_ntop(AF_INET6, &sender_address->sin6_addr , abuf , sizeof(abuf));
          close(recvfd);
          string sapp = abuf;
          return sapp; //let's return the source address
        }
      }
      break;
      case (ICMP6_PACKET_TOO_BIG) : { //path mtu discovery
        struct icmp6_hdr *icmp6_2;
        icmp6_2= (struct icmp6_hdr* ) (my_buffer + sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr));
        if ((icmp6_2->icmp6_id==pid) && (icmp6_2->icmp6_seq==sequence)) {
          mtu = ntohl(icmp6->icmp6_mtu); //let's determine the future mtu
         sequence--;
          char abuf[INET6_ADDRSTRLEN];
          sender_address = (struct sockaddr_in6 *)&ss;
          (void) inet_ntop(AF_INET6, &sender_address->sin6_addr , abuf , sizeof(abuf));
          close(recvfd);
          string sapp = abuf;
          return sapp; //let's return the source address
        }
      }
      break;
    }


  }

  }
  close(recvfd);
  return "";

}

int Analyzer::Sender(string sourceAddress, string destAddress, int hoplimit) {
  int s = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);	/* open raw socket */
  if(s < 0) {
    perror("socket");
    close(s);
    return -1;
  }

  char icmp6PL[8];

  char datagram[1500];
  memset (datagram, 0, sizeof(datagram));

  struct icmp6_hdr *icmp;
  icmp = (struct icmp6_hdr *) (datagram);
  icmp->icmp6_type = 128;
  icmp->icmp6_code = 0;
  icmp->icmp6_cksum = 0;
  icmp->icmp6_id =pid;
  icmp->icmp6_seq=sequence;
  memset(&icmp6PL, 0, sizeof(icmp6PL));

  in6_addr in;
  in6_addr *p_in=&in;
  int res1=inet_pton(AF_INET6, sourceAddress.c_str() , p_in);

  in6_addr in2;
  in6_addr *p_in2=&in2;
  int res2=inet_pton(AF_INET6, destAddress.c_str() , p_in2); //destination IP

  struct sockaddr_in6 sin;

  bzero(&sin,sizeof(sin));
  int res = inet_pton(AF_INET6, destAddress.c_str() , &sin.sin6_addr);
  if (res==0) {
    printf("error with ip \n");
    exit(1);
  }
//    sin.sin6_port=htons(1025);
  sin.sin6_family=AF_INET6;

  int recvfd = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  if(recvfd < 0) {
    perror("socket");
    close(recvfd);
    return -1;
  }

 // int on = 1;
//  if (setsockopt(s, IPPROTO_IPV6, 62, &on, sizeof(on))== -1) printf("problems frag")  ;
  // 62 = IPV6_DONTFRAG



  if (setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hoplimit,
      sizeof(hoplimit)) == -1)
      perror("setsockopt IPV6_UNICAST_HOPS");

  if (sendto (s,		/* our socket */
        datagram,	/* the buffer containing header and data */
   //     sizeof(datagram),	/* total length of our datagram */
        mtu-40, //8 bytes of ICMPv6 header + 40 bytes of IPv6 header
        0,		/* routing flags, normally always 0 */
        (struct sockaddr *) &sin,	/* socket addr, just like in */
        sizeof (sin)) < 0)		/* a normal send() */
    { close(s);
      exit(1);
     }
  else return recvfd;

}

int Analyzer::FragSender(string ipv6In, string ipv6Out, string ipv4In, string ipv4Out, int hoplimit) {
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
      iph->ip_len = mtu;
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
      ip6->ip6_plen = htons(mtu - 40);
      ip6->ip6_nxt = 58; //58 = IPPROTO_ICMP6
      ip6->ip6_hlim = hoplimit;

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


void Analyzer::setIpRef(string ipApp) {
  ipRef = ipApp;
}

void Analyzer::setIpRefPath(string pathApp) {
  ipRefPath = pathApp;
}

void Analyzer::setOption(string opApp) {
  option = opApp;
}

//checks if a tunnel is a vantage point.. and stores it into vp, in future to implement a list instead of vp
int Analyzer::setVanPoint(Segment s) {
  if (s.getIsTunnel()==true) {
    vp=s;
    return 1;
  }
  else return 0;
}

//for now just resolves into ipv4 addresses
string Analyzer::resolve(string hostn) {
  IfAna ia;
  return ia.resolve(hostn);
}

Segment Analyzer::analyse(string a,string b) {
  SegmentAna sa;
  sa.setIpRefPath(ipRefPath);
  sa.setIpRef(ipRef);
  sa.setOption(option);
  Segment s;
  int addA; //if a is an ipv4 address (1) or not (0)
  int addB;
  in_addr in;
  in_addr *p_in=&in;
  const char* s_addr=a.c_str();
  in_addr in2;
  in_addr *p_in2=&in2;
  const char* s_addr2=b.c_str();
  int res=inet_pton(AF_INET, s_addr, p_in);
  int res2=inet_pton(AF_INET, s_addr2, p_in2);
  if(res==1){
     addA = 1;
     if(res2==1){
        addB = 1;
     }
     else addB=0;
  }
  else {
    addA=0;
    if(res2==1){
       addB = 1;
    }
    else addB=0;
  }
  switch(addA){
    case(1):
      if (addB==1) s=sa.create("","",a,b);
      else {
        if (resolve(b)!="") s=sa.create("",b,a,resolve(b));
        else {
          if (option == "-v") {
            printf("UNKNOWN2 ");
            printf("%s -> %s\n",a.c_str(),b.c_str());
          }
          else cerr <<"error resolving interfaces"<<endl;
          exit(2);
        }
      }
      break;
    case(0):
      if (addB==1) {
        if (resolve(a)!="") s=sa.create(a,"",resolve(a),b);
        else {
          if (option == "-v") {
            printf("UNKNOWN1 ");
            printf("%s -> %s\n",a.c_str(),b.c_str());
	  }
          else cerr <<"error resolving interfaces"<<endl;
          exit(2);
        }
      }
      else if ((resolve(b)!="")&&(resolve(a)!="")) s=sa.create(a,b,resolve(a),resolve(b));
           else {
             if (option == "-v") {
	       if ((resolve(a)=="")&&(resolve(b)=="")) printf("UNKNOWN12 ");
	       else if (resolve(a)=="") printf("UNKNOWN1 ");
	            else printf("UNKNOWN2 ");
               printf("%s -> %s\n",a.c_str(),b.c_str());
             }
             else cerr <<"error resolving interfaces"<<endl;
             exit(2);
           }
      break;
  }

 // cout <<s.getHostnamein()<<endl;
  s=sa.analyse(s);
  setVanPoint(s);
  return s;
}

string Analyzer::resolve6(string hostn) {
  IfAna ia;
  return ia.resolve6(hostn);
}

void Analyzer::analyse(string a) { //if we are in the case of tunneltrace B with B = IPv6
  string ipDest;
  SegmentAna sa;
  sa.setIpRefPath(ipRefPath);
  sa.setIpRef(ipRef);
  sa.setOption(option);
  Segment s1;
  in6_addr in;
  in6_addr *p_in=&in;
  int res=inet_pton(AF_INET6, a.c_str() , p_in);
  if(res==1) {
    ipDest = a;  // a = IPv6 address
  }
  else {
    if (resolve6(a)!="") {
      ipDest = resolve6(a); //a = hostname
    }
    else {
      cerr <<"error resolving interfaces"<<endl;
      exit(2);
    }
  }
  printf("30 Hops MAX\n");
  NameIpAna n1;
  string result = "";
  string previous = "";
  string ownIp = getOwnIp(ipDest); //to find the IP of the machine where Tunneltrace is running
  while ((result != "ok")&&(sequence<30)) {
    sequence++;
    relsequence++;
    previous = result; //to remember the previous node, for finding segments
    if (vp4dest=="") result = Receiver(Sender(ownIp,ipDest,sequence));
    else result = Receiver(FragSender(ownIp, ipDest, vp4source, vp4dest,relsequence));
    if (result!="ok") {
      if (result=="") {
        int tentative = 0;
        if (vp4dest!="") { //we tryed once fragmented traceroute6 but it didnt' work, so let's
          mtu = appmtu; //put everything back as it was before
          appmtu = 0;
          if (vp4destapp=="") {
            vp4source = "";
            vp4dest = "";
            relsequence = 0;
          }
          else {
            vp4source = vp4sourceapp;
            vp4dest = vp4destapp;
            relsequence = relsequenceapp;
            vp4sourceapp = "";
            vp4destapp = "";
            relsequenceapp = 0;
          }
        }
        else  tentative = 1;
        while ((tentative<3)&&(result=="")) {
          if (vp4dest=="") result = Receiver(Sender(ownIp,ipDest,sequence));
          else result = Receiver(FragSender(ownIp, ipDest, vp4source, vp4dest,relsequence));
          tentative++;
        }
        if (result=="") { //node unreachable
          printf("%i *\n",sequence);
        }
        else {
          if ((result!="ok")&&(result!=ipDest)){ //node found
               printf("%i %s(%s) %i\n",sequence,n1.resolvehost6(result).c_str(),result.c_str(),mtu);
               if (previous!="") { //we have a valid segment to analyze
                 s1 = sa.create(previous,result);
                 Segment s2;
                 s2=sa.analyse(s1);
                 string ipv6in,ipv6out;
                 if (s2.getIsTunnel()==true) {
                   //let's set the outern endpoint as a vantagePoint for fragmented Traceroute6:
                   if (vp4source != "") {
                     vp4sourceapp = vp4source; //we already used a functional vantagepoint
                     vp4destapp = vp4dest;     //so let's back it up in case this new one doesn't work
                     relsequenceapp = relsequence;
                   }
                   vp4source = s2.getIpv4in();
                   vp4dest = s2.getIpv4out();
                   relsequence = 0;
                   appmtu = mtu;
                   mtu = 1500;
                   printf("%s(%s) -> %s(%s)\n",s2.getHostnamein().c_str(),s2.getIpv4in().c_str(),
                   s2.getHostnameout().c_str(),s2.getIpv4out().c_str());
                   if (s2.getIpv6in()=="") ipv6in = s1.getIpv6in();
                   else ipv6in = s2.getIpv6in();
                   if (s2.getIpv6out()=="") ipv6out = s1.getIpv6in();
                   else ipv6out = s2.getIpv6out();
                   printf("%s -> %s ; CONFIDENCE %i/10\n",ipv6in.c_str(),ipv6out.c_str(),s2.getConfidence());
                 }
               }
             }
             else if (result==ipDest) result = "ok";
        }
       }
       else { //node found
         if (result!=ipDest) {
           printf("%i %s(%s) %i\n",sequence,n1.resolvehost6(result).c_str(),result.c_str(),mtu);
           if (previous!="") { //we have a valid segment to analyze
             s1 = sa.create(previous,result);
             Segment s2;
             s2=sa.analyse(s1);
             string ipv6in,ipv6out;
             if (s2.getIsTunnel()==true) {
               //let's set the outern endpoint as a vantagePoint for fragmented Traceroute6:
               if (vp4source != "") {
                 vp4sourceapp = vp4source; //we already used a functional vantagepoint
                 vp4destapp = vp4dest;     //so let's back it up in case this new one doesn't work
                 relsequenceapp = relsequence;
               }
               vp4source = s2.getIpv4in();
               vp4dest = s2.getIpv4out();
               relsequence = 0;
               appmtu = mtu;
               mtu = 1500;
               printf("%s(%s) -> %s(%s)\n",s2.getHostnamein().c_str(),s2.getIpv4in().c_str(),
               s2.getHostnameout().c_str(),s2.getIpv4out().c_str());
               if (s2.getIpv6in()=="") ipv6in = s1.getIpv6in();
               else ipv6in = s2.getIpv6in();
               if (s2.getIpv6out()=="") ipv6out = s1.getIpv6in();
               else ipv6out = s2.getIpv6out();
               printf("%s -> %s ; CONFIDENCE %i/10\n",ipv6in.c_str(),ipv6out.c_str(),s2.getConfidence());
             }
           }
         }
         else result = "ok";
       }
    }
  }

  if (result=="ok") {
    printf("%i %s(%s) %i\n",sequence,n1.resolvehost6(ipDest).c_str(),ipDest.c_str(),mtu);
    if (previous!="") { //we have a valid segment to analyze
      s1 = sa.create(previous,result);
      Segment s2;
      s2=sa.analyse(s1);
      string ipv6in,ipv6out;
      if (s2.getIsTunnel()==true) {
        printf("%s(%s) -> %s(%s)\n",s2.getHostnamein().c_str(),s2.getIpv4in().c_str(),
        s2.getHostnameout().c_str(),s2.getIpv4out().c_str());
        if (s2.getIpv6in()=="") ipv6in = s1.getIpv6in();
        else ipv6in = s2.getIpv6in();
        if (s2.getIpv6out()=="") ipv6out = s1.getIpv6in();
        else ipv6out = s2.getIpv6out();
        printf("%s -> %s ; CONFIDENCE %i/10\n",ipv6in.c_str(),ipv6out.c_str(),s2.getConfidence());
      }
    }
  }
}



//returns the vantage point.. in the future the list of vp of a path
Segment Analyzer::getVanPoint() {
  return vp;
}
