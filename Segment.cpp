#include <stdlib.h>
#include <string>
#include "Interface.h"
#include "Segment.h"

using namespace std;

Segment::Segment() {
  init();
}

void Segment::init() {

  mtu = 1500;
  midRt = 0;
  isTunnel = false;
  confidence = 0;

}

//metodi set

void Segment::setMtu(int mtuapp) {
  mtu = mtuapp;
}

void Segment::setMidRt(long midrtapp) {
  midRt = midrtapp;
}

void Segment::setIsTunnel(bool istunnelapp) {
  isTunnel = istunnelapp;
}

void Segment::setTunnelType(string type) {
  tunnelType = type ;
}

/*void Segment::increaseIn(int howmuch) {
  tunnelIncert = tunnelIncert + howmuch;
}*/

void Segment::increaseConf(int howmuch) {
  confidence = confidence + howmuch;
}

void Segment::addIpv4in(string ipv4in) {
  if_in.setIpv4(ipv4in);
}

void Segment::addIpv6in(string ipv6in) {
  if_in.setIpv6(ipv6in);
}

void Segment::addHostnamein(string hostnamein) {
  if_in.setNomi(hostnamein);
}

void Segment::addIpv4out(string ipv4out) {
  if_out.setIpv4(ipv4out);
}

void Segment::addIpv6out(string ipv6out) {
  if_out.setIpv6(ipv6out);
}

void Segment::addHostnameout(string hostnameout) {
  if_out.setNomi(hostnameout);
}

//metodi get

int Segment::getMtu() {
  return mtu;
}

long Segment::getMidRt() {
  return midRt;
}

int Segment::getConfidence() {
  return confidence;
}

bool Segment::getIsTunnel() {
  return isTunnel;
}

string Segment::getIpv4in() {
  return if_in.getIpv4();
}

string Segment::getIpv6in() {
  return if_in.getIpv6();
}

string Segment::getHostnamein() {
  return if_in.getNomi();
}

string Segment::getIpv4out() {
  return if_out.getIpv4();
}

string Segment::getIpv6out() {
  return if_out.getIpv6();
}

string Segment::getHostnameout() {
  return if_out.getNomi();
}

