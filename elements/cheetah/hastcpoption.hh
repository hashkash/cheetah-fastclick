#ifndef CLICK_HasTCPOption_HH
#define CLICK_HasTCPOption_HH
#include <click/batchelement.hh>
#include <click/glue.hh>
#include <click/tcphelper.hh>
#include <clicknet/ip.h>
#include <click/vector.hh>
#include <click/string.hh>
#include "cheetah.hh"

CLICK_DECLS

class DPDKDevice;

/*
 * =c
 * HasTCPOption(KEYWORD)
 *
 * =s package
 * Summary description
 *
 * =d
 *
 * Long description of the element
 *
 * The keywords are:
 *
 * =e
 * HasTCPOption() -> Print()
 */
class HasTCPOption : public BatchElement, Cheetah {

 public:

  HasTCPOption() CLICK_COLD;
  ~HasTCPOption() CLICK_COLD;

  const char *class_name() const		{ return "HasTCPOption"; }
  const char *port_count() const		{ return "1/2"; }

  int configure(Vector<String> &conf, ErrorHandler *errh) override CLICK_COLD;
  int initialize(ErrorHandler *errh) override CLICK_COLD ;

  void push_batch(int, PacketBatch *) override;


private:


};

CLICK_ENDDECLS
#endif
