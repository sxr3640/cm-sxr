#include <iostream>
#include <stdlib.h>
#include <string>
#include <fstream>
#include <sys/types.h>
#include <unistd.h>
#include "Interface.h"
#include "Segment.h"
#include "Analyzer.h"
#include "NameIpAna.h"

using namespace std;

string cut_it(string spath) {    //获得当前路径
  string src = spath;
  string src2 ;
  char prova[40]="";
  char app[40]="";
  int ix = src.size() - 1;
  while ((src[ix]!='/')&&(ix>0)) ix--;
  if (src[ix-1]!='.') {
    int ix2=2;
    int i=0;
    ix++;
    while (ix2<ix) {
      prova[i]=src[ix2];
      ix2++;
      i++;
    }
    src2=prova;
  }
  else src2="";
  return src2;
}
string name_it(string sname) {
  string src = sname;
  string src2 ;
  char prova[40]="";
  char app[40]="";
  int ix = src.size() - 1;
  while ((src[ix]!='/')&&(ix>=0)) ix--;
    int ix2=0;
    ix++;
    while (ix<src.size()) {
      prova[ix2]=src[ix];
      ix2++;
      ix++;
    }
    src2=prova;
  return src2;
}
void usage(string programName) {
  printf("Usage : %s [ -h reference IPv6 ] [ -v ] <source IPv4> <dest IPv4> \n",programName.c_str());
  printf("      : %s [ -h reference IPv6 ] <dest IPv6> \n",programName.c_str());
  printf("    The reference IPv6 address must be pingable from the tunnel\n");
  printf("    endpoints. If not specified on the command line, it may be\n");
  printf("    specified in the file /etc/tunneltrace.ip\n");
  exit(1);
}

int main(int argc, char *argv[])
{
 string ipv6in,ipv6out,progName;
 progName = name_it(argv[0]);
 //       cout<<progName.c_str()<<endl;
 if (geteuid()!=0) {
   cerr<<"Error, you must be root to run tunneltrace"<<endl;
   exit(1);
 }

 switch(argc) {
   case (2) : {
     string app1;
// app1 = cut_it(argv[0]) + "ipref"; //to find the path of the file "tunneltrace.ip"
     app1 = cut_it(argv[0]);//to find the path of the file "tunneltrace.ip" and 6bone.db
     Analyzer a1;
     a1.setIpRefPath(app1); //set the path where tunneltrace is running
     // a1.setIpRefPath("/etc/"); //set the path of the file "tunneltrace.ip"
     a1.analyse(argv[1]);
     // s1=a1.getVanPoint();
     exit(0);
     }
   break;

 case (3) : {
   string app1;
// app1 = cut_it(argv[0]) + "ipref"; //to find the path of the file "tunneltrace.ip"
   app1 = cut_it(argv[0]);//to find the path of the file "tunneltrace.ip"
   Analyzer a1;
   Segment s1;
   a1.setIpRefPath(app1); //set the path where tunneltrace is running
   // a1.setIpRefPath("/etc/"); //set the path of the file "tunneltrace.ip"
   s1=a1.analyse(argv[1],argv[2]);
   // s1=a1.getVanPoint();
   printf("%s(%s) -> %s(%s)\n",s1.getHostnamein().c_str(),s1.getIpv4in().c_str(),
   s1.getHostnameout().c_str(),s1.getIpv4out().c_str());
   if (s1.getIpv6in()=="") ipv6in = "::";
   else ipv6in = s1.getIpv6in();
   if (s1.getIpv6out()=="") ipv6out = "::";
   else ipv6out = s1.getIpv6out();
   printf("%s -> %s ; CONFIDENCE %i/10\n",ipv6in.c_str(),ipv6out.c_str(),s1.getConfidence());
   exit(0);
   }
 break;
 case (4) : {
   string check = argv[1];
   if (check =="-v") { // ipref set prompt
     string app1;
// app1 = cut_it(argv[0]) + "ipref"; //to find the path of the file "tunneltrace.ip"
     app1 = cut_it(argv[0]);//to find the path of the file "tunneltrace.ip"
     Analyzer a1;
     Segment s1;
     a1.setIpRefPath(app1); //set the path where tunneltrace is running
     a1.setOption("-v");
   // a1.setIpRefPath("/etc/"); //set the path of the file "tunneltrace.ip"
     s1=a1.analyse(argv[2],argv[3]);
   // s1=a1.getVanPoint();
     printf("%s(%s) -> %s(%s) ",s1.getHostnamein().c_str(),s1.getIpv4in().c_str(),
     s1.getHostnameout().c_str(),s1.getIpv4out().c_str());
     if (s1.getIpv6in()=="") ipv6in = "::";
     else ipv6in = s1.getIpv6in();
     if (s1.getIpv6out()=="") ipv6out = "::";
     else ipv6out = s1.getIpv6out();
     printf("%s -> %s %i/10\n",ipv6in.c_str(),ipv6out.c_str(),s1.getConfidence());
     exit(0);
   }
   else {
    if (check == "-h") {
      Analyzer a1;
      Segment s1;
      string app1;
// app1 = cut_it(argv[0]) + "ipref"; //to find the path of the file "tunneltrace.ip"
      app1 = cut_it(argv[0]);//to find the path of the file "tunneltrace.ip"
      a1.setIpRefPath(app1); //set the path where tunneltrace is running
      a1.setIpRef(argv[2]);
      // a1.setIpRefPath("/etc/"); //set the path of the file "tunneltrace.ip"
      a1.analyse(argv[3]);
      // s1=a1.getVanPoint();
      exit(0);
    }
   }
 }
  break;
 case (5) : {
   string check = argv[1];
   if (check =="-h") { // ipref set prompt
     Analyzer a1;
     Segment s1;
     string app1;
// app1 = cut_it(argv[0]) + "ipref"; //to find the path of the file "tunneltrace.ip"
     app1 = cut_it(argv[0]);//to find the path of the file "tunneltrace.ip"
     a1.setIpRefPath(app1); //set the path where tunneltrace is running
     a1.setIpRef(argv[2]);
     s1=a1.analyse(argv[3],argv[4]);
  // s1=a1.getVanPoint();
     printf("%s(%s) -> %s(%s)\n",s1.getHostnamein().c_str(),s1.getIpv4in().c_str(),
     s1.getHostnameout().c_str(),s1.getIpv4out().c_str());
     if (s1.getIpv6in()=="") ipv6in = "::";
     else ipv6in = s1.getIpv6in();
     if (s1.getIpv6out()=="") ipv6out = "::";
     else ipv6out = s1.getIpv6out();
     printf("%s -> %s ; CONFIDENCE %i/10\n",ipv6in.c_str(),ipv6out.c_str(),s1.getConfidence());
     exit(0);
   }
 }
  break;
  case (6) : {
    string check = argv[1];
    if (check =="-h") { // ipref set prompt
      string check2 = argv[3];
      if (check2 == "-v") {
        Analyzer a1;
        Segment s1;
        string app1;
// app1 = cut_it(argv[0]) + "ipref"; //to find the path of the file "tunneltrace.ip"
        app1 = cut_it(argv[0]);//to find the path of the file "tunneltrace.ip"
        a1.setIpRefPath(app1); //set the path where tunneltrace is running
        a1.setIpRef(argv[2]);
        a1.setOption("-v");
        s1=a1.analyse(argv[4],argv[5]);
   // s1=a1.getVanPoint();
        printf("%s(%s) -> %s(%s) ",s1.getHostnamein().c_str(),s1.getIpv4in().c_str(),
        s1.getHostnameout().c_str(),s1.getIpv4out().c_str());
        if (s1.getIpv6in()=="") ipv6in = "::";
        else ipv6in = s1.getIpv6in();
        if (s1.getIpv6out()=="") ipv6out = "::";
        else ipv6out = s1.getIpv6out();
        printf("%s -> %s %i/10\n",ipv6in.c_str(),ipv6out.c_str(),s1.getConfidence());
        exit(0);
      }
    }
    if (check =="-v") { // ipref set prompt
      string check2 = argv[2];
      if (check2 == "-h") {
        Analyzer a1;
        Segment s1;
        string app1;
// app1 = cut_it(argv[0]) + "ipref"; //to find the path of the file "tunneltrace.ip"
        app1 = cut_it(argv[0]);//to find the path of the file "tunneltrace.ip"
        a1.setIpRefPath(app1); //set the path where tunneltrace is running
        a1.setIpRef(argv[3]);
        a1.setOption("-v");
        s1=a1.analyse(argv[4],argv[5]);
 // s1=a1.getVanPoint();
        printf("%s(%s) -> %s(%s) ",s1.getHostnamein().c_str(),s1.getIpv4in().c_str(),
        s1.getHostnameout().c_str(),s1.getIpv4out().c_str());
        if (s1.getIpv6in()=="") ipv6in = "::";
        else ipv6in = s1.getIpv6in();
        if (s1.getIpv6out()=="") ipv6out = "::";
        else ipv6out = s1.getIpv6out();
        printf("%s -> %s %i/10\n",ipv6in.c_str(),ipv6out.c_str(),s1.getConfidence());
        exit(0);
      }
    }
  }
   break;

  }
  usage(progName);
  exit(1);

}


