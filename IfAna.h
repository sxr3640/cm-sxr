#ifndef IFANA_H
#define IFANA_H
#include <stdlib.h>
#include <string>
#include <stdio.h>
#include "NameIpAna.h"
#include "Interface.h"
#include "Segment.h"

using namespace std;

class IfAna {

  public :

    IfAna();
    ~IfAna();

    //for resolving a hostname into ipv4 or ipv6
    string resolve(string);
    string resolve6(string);
    //for analysing and updating a given segment
    Segment analyseIf(Segment);
    //for analysing and updating an Interface
    Interface analyseIf(Interface);
    //anlyse(IpPacket); -> analyse data inside an IpPacket(resolve addresses and hostname)

  private :

    NameIpAna n1;
};
#endif
