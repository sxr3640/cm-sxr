#ifndef INTERFACE_H
#define INTERFACE_H
#include <stdlib.h>
#include <string>


using namespace std;

class Interface
{
           public :
                    Interface();

                    //set methods
                    void setIpv4(string);
                    void setIpv6(string);

                    void setNomi(string);

                    //get methods
                    string getIpv4();
                    string getIpv6();
                    string getNomi();

           private :
                    string ipv4;
                    string ipv6;
                    string nomi;

                    void init();

};

#endif






