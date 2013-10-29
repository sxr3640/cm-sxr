#include <stdlib.h>
#include <string>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "NameIpAna.h"
#include "Segment.h"
#include "Interface.h"
#include <cstring>
using namespace std;

NameIpAna::NameIpAna() {
}

string NameIpAna::getIp(string hostname,int what) //what -> resolve into 1 - ipv4 or 2 - ipv6
{ struct addrinfo hints;
  struct addrinfo *result;
  char buf[NI_MAXHOST];
  memset (&hints, 0, sizeof (hints));
  if (what==1) hints.ai_family = AF_INET;
  else hints.ai_family = AF_INET6;
  string s;
  hints.ai_socktype = SOCK_DGRAM;

  int ret=getaddrinfo(hostname.c_str(),NULL,&hints,&result);
  if (ret==0) {
  getnameinfo(result->ai_addr, result->ai_addrlen, buf, NI_MAXHOST,NULL, 0,NI_NUMERICHOST);
  s = buf;
  freeaddrinfo(result);
  return s;
  }

  else return "";
}

string NameIpAna::getHost(string ip) {

char             buf[NI_MAXHOST];
struct addrinfo *p_Addrs;
struct addrinfo  Hints;
int              ret;
char*            app;

memset (&Hints, 0, sizeof (Hints));
Hints.ai_family = PF_UNSPEC;
Hints.ai_socktype = SOCK_DGRAM;

ret = getaddrinfo (ip.c_str(), NULL, &Hints, &p_Addrs);
if (ret != 0)  return "";

//   cout << p_Addrs->ai_addr;
else {
ret = getnameinfo (p_Addrs->ai_addr, p_Addrs->ai_addrlen,
                   buf, sizeof (buf), NULL, 0, NI_NAMEREQD);
freeaddrinfo (p_Addrs);
if (ret != 0) return "";
else {
  app=buf;
  return app;
}
}
}


//FOR EVERY FUNCTION : Value "" - Resolver failed

string NameIpAna::resolveip(string hostname) {
  return getIp(hostname,1);
}

string NameIpAna::resolveip6(string hostname) {
  return getIp(hostname,2);                 //获得指定主机的IPV6地址
}

string NameIpAna::resolvehost(string ipv4) {
  return getHost(ipv4);
}

string NameIpAna::resolvehost6(string ipv6) {
  return getHost(ipv6);
}

string NameIpAna::resolveip(Interface i1) {
  return getIp(i1.getIpv4(),1);
}

string NameIpAna::resolveip6(Interface i1) {
  return getIp(i1.getIpv6(),2);
}

string NameIpAna::resolvehost(Interface i1) {
  return getHost(i1.getNomi());
}

string NameIpAna::resolvehost6(Interface i1) {
  return getHost(i1.getNomi());
}

