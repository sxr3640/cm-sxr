#ifndef RAWSENDER_H
#define RAWSENDER_H

#include <netdb.h>
#include <netinet/in_systm.h>
#include <net/route.h>
#include <stdlib.h>
#include <string>
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/if.h>

using namespace std;

class RawSender {

  public :

    RawSender();
    ~RawSender();
    //Unit for Sending/Fragmenting Packets
    int SendPacket(char*,int);

  private :

      unsigned short csum (unsigned short *, int);
};
#endif
