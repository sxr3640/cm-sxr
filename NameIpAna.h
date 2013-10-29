#ifndef NAMEIPANA_H
#define NAMEIPANA_H
#include <stdlib.h>
#include <string>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "Segment.h"
#include "Interface.h"

using namespace std;

class NameIpAna {

  public :

     NameIpAna();

     //for resolving hostname in address ipv4 or ipv6
     string  resolveip(string);
     string  resolveip6(string);
     //for resolving addresse ipv4 or ipv6 into hostname
     string resolvehost(string);
     string resolvehost6(string);
     //for resolving interface hostname into address ipv4 or ipv6
     string resolveip(Interface);
     string resolveip6(Interface);
     //for resolving interface address ipv4 or ipv6 into hostname
     string resolvehost(Interface);
     string resolvehost6(Interface);

  private :
     string getIp(string,int);
     string getHost(string);

};
#endif
