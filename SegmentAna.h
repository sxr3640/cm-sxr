#ifndef SEGMENTANA_H
#define SEGMENTANA_H
#include <stdlib.h>
#include <string>
#include <stdio.h>
#include "Interface.h"
#include "Segment.h"
#include "IfAna.h"

using namespace std;

class SegmentAna {

  public :

    SegmentAna();

    Segment create(string,string,string,string);
    Segment create(string,string);
    Segment analyse(Segment);
    void setIpRef(string);
    void setIpRefPath(string);
    void setOption(string);

  private :

    Segment updateTun(Segment,int); //updates or creates the tunnel, with the int value of Uncertainy(incertezza)
    string my_itoa(int, int);
    int my_atoi(string, int);
    string calculate_ip(string);
    string ipRef; //address of reference, for the spoofing analizers, to be set with the -h option by the user
    string ipRefPath;//where the file "ipref" is located
    string option; //determines if we used the "-v" option for parametric output

};
#endif
