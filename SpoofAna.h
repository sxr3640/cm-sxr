#ifndef SPOOFANA_H
#define SPOOFANA_H

#include <netdb.h>
#include <netinet/in_systm.h>
#include <net/route.h>
#include <sys/time.h>
#include <stdlib.h>
#include <string>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#  define TH_SYN	0x02

#define P 25


using namespace std;

const size_t BUFFER_LENGTH = 65536;
const size_t ADO_BUF_SIZE = 1024;

class SpoofAna {

  public :

    SpoofAna();
    ~SpoofAna();
    //sayes if the endpoint of a tunnel is pingable
    int InjectedPing(string,string,string);
    //gives out the ipv6 address of a tunnel endpoint with hope limit manipulation
    string DyingPacket(string,string,string);
    //gives out the ipv6 address of a tunnel endpoint with ping-pong technique
    string PingPongPacket(string,string,string,string);
 //   string PingPongPacket(string,string,string);
    //" " " " " " with bouncing technique, to implement furtherly for other usercases, not
    //useful for usercase : -> tunneltrace a b (a,b=ipv4 addresses)
    string BouncingPacket(string,string,string,string);
    //the same as injected Ping but with fragments
    int FragmentedInjectedPing(string,string,string);
    string getOwnIp();
    void setIpRef(string);
    void setIpRefPath(string);

  private :
    //options : 0 = injected ping, 1 = DyingPacket, 2 = PingPongPacket
    int Sender(string, string, string, string, int); // returns descriptor of receiving socket, -1 - sending error...
    string Receiver(int,int); // "" : error receiving
    unsigned short in_cksum(unsigned short *, int);
    unsigned short csum (unsigned short *, int);
    unsigned short pseudo_check(struct in6_addr, struct in6_addr, void *, int, int);
    int sequence; //sequence of the operation (to put in icmpv6 seq data field)
    int pid; //process -id of the actual process (to put in icmpv6 id data field)
    string ipRef;//reference ip with which i try everything, of a valid ipv6 interface
    string ipRefPath;//where the file "ipref" is located

};
#endif
