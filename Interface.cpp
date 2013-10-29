#include <iostream>
#include <stdlib.h>
#include <string>
#include "Interface.h"

using namespace std;


  Interface::Interface() {
    //variable initialization
    init();
  }

  void Interface::init() {

    ipv4="";   //
    ipv6="";
    nomi="";             //
    return;
  }
//set methods
  void Interface::setIpv4(string addr) {
    ipv4=addr;
    return;
  }

  void Interface::setIpv6(string addr) {
    ipv6=addr;
    return;
  }


  void Interface::setNomi(string hostname) {
    nomi=hostname;
    return;
  }

 //get methods

 string Interface::getIpv4() {
   return ipv4;
 }

 string Interface::getIpv6() {
   return ipv6;
 }

 string Interface::getNomi() {
   return nomi;
 }



