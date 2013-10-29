#ifndef SEGMENT_H
#define SEGMENT_H
#include <stdlib.h>
#include <string>
#include "Interface.h"

using namespace std;

class Segment {

  public :
           Segment();

           //set methods
           void setMtu(int);
           void setMidRt(long);
           void setIsTunnel(bool);
           void setTunnelType(string);
           void increaseConf(int); //originally set to 15
           //data relative to interfaces.., when adding data, just select the data you are adding to true
           //the AND bool to bool gives the right output
           void addIpv4in(string) ;
           void addIpv6in(string) ;
           void addHostnamein(string);
           void addIpv4out(string) ;
           void addIpv6out(string) ;
           void addHostnameout(string) ;

           //get methods

           int getMtu();
           bool getIsTunnel();
           long getMidRt();
           int getConfidence();
           string getIpv4in();
           string getIpv6in();
           string getHostnamein();
           string getIpv4out();
           string getIpv6out();
           string getHostnameout();

  private :


           Interface if_in;
           Interface if_out;
           int mtu;
           long midRt;
           bool isTunnel;
           string tunnelType;
           int confidence;
           void init();
};
#endif
