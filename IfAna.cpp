#include <stdlib.h>
#include <string>
#include <stdio.h>
#include "NameIpAna.h"
#include "Interface.h"
#include "Segment.h"
#include "IfAna.h"

using namespace std;

IfAna::IfAna() {
}

IfAna::~IfAna() {
}

string IfAna::resolve(string hostname) {
  return n1.resolveip(hostname);
}

string IfAna::resolve6(string hostname) {
  return n1.resolveip6(hostname);
}

Segment IfAna::analyseIf(Segment s1) {
  string app,app1;
  if ((app=s1.getHostnamein())!="") { //Interface has hostname
    if ((s1.getIpv4in()=="")&&((app1=n1.resolveip(app))!="")) {
      s1.addIpv4in(app1);
    }
    if ((s1.getIpv6in()=="")&&((app1=n1.resolveip6(app))!="")) {
 //     printf("DNS : ipv6in %s \n",app1.c_str());
      s1.addIpv6in(app1);
    }
  }
  else { if (s1.getIpv4in()!="") { //Interface has ipv4
           if ((app=n1.resolvehost(s1.getIpv4in()))!="") {
             s1.addHostnamein(app);
             if ((s1.getIpv6in()=="")&&((app1=n1.resolveip6(app))!="")) {
        //       printf("DNS : ipv6in %s \n",app1.c_str());
               s1.addIpv6in(app1);
             }
           }

         }
         else {   //Interface has ipv6
           if ((app=n1.resolvehost6(s1.getIpv6in()))!="") {
             s1.addHostnamein(app);
             if ((s1.getIpv4in()=="")&&((app1=n1.resolveip(app))!="")) {
               s1.addIpv4in(app1);
             }
           }


         }
  }
  if ((app=s1.getHostnameout())!="") { //Interface has hostname
    if ((s1.getIpv4out()=="")&&((app1=n1.resolveip(app))!="")) {
      s1.addIpv4out(app1);
    }
    if ((s1.getIpv6out()=="")&&((app1=n1.resolveip6(app))!="")) {
 //     printf("DNS : ipv6out %s \n",app1.c_str());
      s1.addIpv6out(app1);
    }
  }
  else { if (s1.getIpv4out()!="") { //Interface has ipv4
           if ((app=n1.resolvehost(s1.getIpv4out()))!="") {
             s1.addHostnameout(app);
             if ((s1.getIpv6out()=="")&&((app1=n1.resolveip6(app))!="")) {
      //         printf("DNS : ipv6out %s \n",app1.c_str());
               s1.addIpv6out(app1);
             }
           }

         }
         else {   //Interface has ipv6
           if ((app=n1.resolvehost6(s1.getIpv6out()))!="") {
             s1.addHostnameout(app);
             if ((s1.getIpv4out()=="")&&((app1=n1.resolveip(app))!="")) {
               s1.addIpv4out(app1);
             }
           }


         }
  }
return s1;
}

Interface IfAna::analyseIf(Interface i1) {
  string app,app1;
  if ((app=i1.getNomi())!="") { //Interface has hostname
    if ((i1.getIpv4()=="")&&((app1=n1.resolveip(app))!="")) {
      i1.setIpv4(app1);
    }
    if ((i1.getIpv6()=="")&&((app1=n1.resolveip6(app))!="")) {
      i1.setIpv6(app1);
    }
  }
  else { if (i1.getIpv4()!="") { //Interface has ipv4
           if ((app=n1.resolvehost(i1.getIpv4()))!="") {
             i1.setNomi(app);
             if ((i1.getIpv6()=="")&&((app1=n1.resolveip6(app))!="")) {
               i1.setIpv6(app1);
             }
           }

         }
         else {   //Interface has ipv6
           if ((app=n1.resolvehost6(i1.getIpv6()))!="") {
             i1.setNomi(app);
             if ((i1.getIpv4()=="")&&((app1=n1.resolveip(app))!="")) {
               i1.setIpv4(app1);
             }
           }


         }
  }
  return i1;
}

