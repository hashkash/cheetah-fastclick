#ifndef CLICK_PrintTCPOption_HH
#define CLICK_PrintTCPOption_HH
#include <click/batchelement.hh>
#include <click/glue.hh>
#include <click/tcphelper.hh>
#include <clicknet/ip.h>
#include <click/vector.hh>
#include <click/string.hh>

CLICK_DECLS

/*
 * =c
 * PrintTCPOption(KEYWORD)
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
 * PrintTCPOption()
 */
class PrintTCPOption : public BatchElement, TCPHelper {

 public:

  PrintTCPOption() CLICK_COLD;
  ~PrintTCPOption() CLICK_COLD;

  const char *class_name() const		{ return "PrintTCPOption"; }
  const char *port_count() const		{ return "1/1"; }

  int configure(Vector<String> &conf, ErrorHandler *errh) override CLICK_COLD;
  int initialize(ErrorHandler *errh) override CLICK_COLD ;

  void push_batch(int, PacketBatch *) override;


private:

  uint8_t _kind;
};

CLICK_ENDDECLS
#endif
