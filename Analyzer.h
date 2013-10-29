#ifndef ANALYZER_H
#define ANALYZER_H
#include <iostream>
#include <stdlib.h>
#include <string>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "Segment.h"
#include "SegmentAna.h"
#include "NameIpAna.h"
#include "RawSender.h"

using namespace std;

class Analyzer {

  public :

    Analyzer();
    Segment analyse(string,string);
    Segment getVanPoint();
    void analyse(string);//tunneltrace B, with B = IPv6
    void setIpRef(string);
    void setIpRefPath(string);
    void setOption(string);

  private :

    string getOwnIp(string);
    string Receiver(int);
    int Sender(string,string,int);
    int FragSender(string,string,string,string,int);
    unsigned short in_cksum(unsigned short *, int);
    unsigned short csum (unsigned short *, int);
    unsigned short pseudo_check(struct in6_addr, struct in6_addr, void *, int, int);
    int setVanPoint(Segment);
    string resolve(string);
    string resolve6(string);
    Segment vp;
    string ipRef; //address of reference, for the spoofing analizers, to be set with the -h option by the user
    string ipRefPath;//where the file "ipref" is located
    string option; //determines if we used the "-v" option for parametric output

};
#endif
