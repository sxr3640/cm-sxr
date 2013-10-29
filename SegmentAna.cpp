#include <stdlib.h>
#include <string>
#include <stdio.h>
#include "Interface.h"
#include "Segment.h"
#include "IfAna.h"
#include "SegmentAna.h"
#include "SpoofAna.h"
#include "NameIpAna.h"
#include <cmath>

/*extern "C" {
  #include "findmtu.h"
}*/

using namespace std;
using std::string;
using std::pow;

string digits = "0123456789abcdefghijklmnopqrstuvwxyz";

string SegmentAna::my_itoa(int src, int radix)
{
        return (src >= radix)
        ? my_itoa(src / radix, radix) + digits[src % radix]
        : string() + digits[src];
}


int SegmentAna::my_atoi(string src, int radix)
{
        int dest = 0;

        for (int i=0; i<src.length(); ++i) {
                dest += static_cast<int>(pow(static_cast<double>(radix), (i)))
                * (digits.find(src[src.length()-i-1]));
        }

        return dest;
}

string SegmentAna::calculate_ip(string ip) {
  string src = ip;
  string src2 ;
  char prova[40]="";
  char app[40]="";
  int ix = src.size() - 1;
  while ((src[ix]!=':')&&(ix>0)) ix--;
  if (ix!=(src.size()-1)) {
    int i=0;
    int ix2=ix;
    while (ix2<(src.size()-1)) {
      ix2++;
      prova[i]=src[ix2];
      i++;
    }
    src2=prova;
  }
  else src2="0";
  int risultato = my_atoi(src2, 16);
  int res = (risultato/2)%2;
  if (res==0) risultato++;
  else risultato--;
  src2 = my_itoa(risultato,16);
  int i2=0;
  for (i2;i2<ix;i2++) app[i2]=src[i2];
  string src3=app;
  string src4 = src3 + ':' + src2;
  return src4;
}

SegmentAna::SegmentAna() {
  ipRef = "";
  ipRefPath = "";
  option = "";
}

void SegmentAna::setIpRef(string ipApp) {
  ipRef = ipApp;
}

void SegmentAna::setIpRefPath(string pathApp) {
  ipRefPath = pathApp;
}

void SegmentAna::setOption(string opApp) {
  option = opApp;
}


Segment SegmentAna::updateTun(Segment s1,int conf) {
  if (s1.getIsTunnel()==false) {
      s1.setIsTunnel(true);
      s1.increaseConf(conf);
  }
  else s1.increaseConf(conf);
  return s1;
}

//implemented only for TUNNELTRACE a b with a,b = ipv4,
Segment SegmentAna::create(string a, string b, string ipa, string ipb) {
  Segment s1;
  s1.addHostnamein(a);
  s1.addIpv4in(ipa);
  s1.addHostnameout(b);
  s1.addIpv4out(ipb);
  return s1;
}

//creates a segment by its ipv6 addresses
Segment SegmentAna::create(string ip6a, string ip6b) {
  NameIpAna n1;
  Segment s1;
  s1.addHostnamein(n1.resolvehost6(ip6a));
  s1.addIpv6in(ip6a);
  s1.addHostnameout(n1.resolvehost6(ip6b));
  s1.addIpv6out(ip6b);
  return s1;
}

Segment SegmentAna::analyse(Segment s1) {
  //analyseIf to find hostnames, and ips of interfaces of segment with
  //DNS
  string ipv6In,ipv6Out; //to check for spoofing methods (Dying packet, Ping-Pong packet)
  IfAna ia;
 // Mtufinder mt;
  Segment s2;
  SpoofAna sp1;
  sp1.setIpRefPath("/etc/");
  sp1.setIpRef(ipRef);
  string ownIp;
  int app;
//  bool flag=false;
  s1=ia.analyseIf(s1);
  s1.addIpv6in("");
  s1.addIpv6out("");
  if (s1.getIpv4in()!="" && s1.getIpv4out()!="") {
  ownIp = sp1.getOwnIp();
 // ownIp = "2001:760:4:0:a00:46ff:fecf:eaeb";
  //injected ping for ipv6in
  if (sp1.InjectedPing(ownIp,s1.getIpv4out(),s1.getIpv4in())==1) {
   // printf("injected ping ipv6in worked\n");
    s1=updateTun(s1,5); //injected ping worked for one endpoint
  }
  //injected ping for ipv6out
  if (sp1.InjectedPing(ownIp,s1.getIpv4in(),s1.getIpv4out())==1) {
   // printf("injected ping ipv6out worked\n");
    if (s1.getConfidence()==5) {
      s1=updateTun(s1,2); //injected ping worked for both endpoints
      if (option == "-v") printf("SPOOF12 ");
    }
    else {
      s1=updateTun(s1,5);//injected ping worked only for second endpoint
      if (option == "-v") printf("SPOOF2 ");
    }
  }
  else if (s1.getConfidence()==5) if (option == "-v") printf("SPOOF1 "); //worked for first endpoint only

  //dying packet for ipv6in
  ipv6In = sp1.DyingPacket(ownIp ,s1.getIpv4out(),s1.getIpv4in());
  ipv6Out = sp1.DyingPacket(ownIp,s1.getIpv4in(),s1.getIpv4out());
  if ((ipv6In!="") && (ipv6Out!="")) {
    s1.addIpv6in(ipv6In);
    s1.addIpv6out(ipv6Out);
    s1=updateTun(s1,2);
    if (option == "-v") printf("ENDPOINT12 ");
   // printf("dying packet ipv6in worked\n");
   // printf("dying packet ipv6out worked\n");
  }
  if ((ipv6In!="") && (ipv6Out == "")) {
   // printf("dying packet ipv6in worked\n");
    s1.addIpv6in(ipv6In);
    s1=updateTun(s1,1);
    string strapp = sp1.PingPongPacket(ownIp,calculate_ip(ipv6In),s1.getIpv4out(),s1.getIpv4in());
    if (strapp!="") {
     // printf("ping pong ipv6in worked\n");
      //the calculated ip is right! we received an echo reply with that as ip6source add if strapp=ok
      //else we received the ip6source add from a time-exceed in transit message!
      if (strapp=="ok") ipv6Out = calculate_ip(ipv6In);
      else ipv6Out = strapp;
      s1.addIpv6out(ipv6Out);
      s1=updateTun(s1,1);
      if (option == "-v") printf("ENDPOINT12 ");
    }
    else if (option == "-v") printf("ENDPOINT1 ");
  }
  else {
    if ((ipv6In=="") && (ipv6Out != "")) {
     // printf("dying packet ipv6out worked\n");
      s1.addIpv6out(ipv6Out);
      s1=updateTun(s1,1);
      string strapp = sp1.PingPongPacket(ownIp,calculate_ip(ipv6Out),s1.getIpv4in(),s1.getIpv4out());
      if (strapp!="") {
       // printf("ping pong ipv6out worked\n");
        //the calculated ip is right! we received an echo reply with that as ip6source add if strapp=ok
        //else we received the ip6source add from a time-exceed in transit message!
        if (strapp=="ok") ipv6In = calculate_ip(ipv6Out);
        else ipv6In = strapp;
        s1.addIpv6in(ipv6In);
        s1=updateTun(s1,1);
        if (option == "-v") printf("ENDPOINT12 ");
      }
      else if (option == "-v") printf("ENDPOINT2 ");
    }
  }
  if (s1.getConfidence()==0) { //spoofing techniques didn't work
    s1=ia.analyseIf(s1);
    if ((s1.getIpv4in()!="")&&(s1.getIpv4out()!="")&&(s1.getIpv6in()!="")&&(s1.getIpv6out()!="")) {
     // printf("resolved tunnel with DNS\n");
      s1=updateTun(s1,1);
  //    if (option == "-v") printf("DNS12 ");
    }
    else {
      if (s1.getIpv6in()!="") if (option == "-v") printf("DNS1 ");
      if (s1.getIpv6out()!="") if (option == "-v") printf("DNS2 ");
    }
  }
  else {
    if (option == "-v") {
      if (sp1.FragmentedInjectedPing(ownIp,s1.getIpv4in(),s1.getIpv4out())==1) {
        if (sp1.FragmentedInjectedPing(ownIp,s1.getIpv4out(),s1.getIpv4in())==1) printf("FRAG12 ");
        else printf("FRAG2 ");
      }
      else if (sp1.FragmentedInjectedPing(ownIp,s1.getIpv4out(),s1.getIpv4in())==1) printf("FRAG1 ");
    }
  }
  //analyse with MTUMethod, works only if i have the ipv6Out address
  //if (s1.getIpv6out()!="") s1.setMtu(principal((char *)s1.getIpv6out().c_str()));
 /* app=mt.getMtu(s1.getHostnameout());
  if (app!=1) {
    s1.setMtu(app);
    if (app<1500) s1=updateTun(s1,1);
  }*/
  }
  return s1;
}
