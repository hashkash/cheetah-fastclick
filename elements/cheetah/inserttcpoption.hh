#ifndef CLICK_InsertTCPOption_HH
#define CLICK_InsertTCPOption_HH
#include <click/batchelement.hh>
#include <click/glue.hh>
#include <click/tcphelper.hh>
#include <clicknet/ip.h>
#include <click/vector.hh>
#include <click/string.hh>

CLICK_DECLS

/*
 * =c
 * InsertTCPOption(KEYWORD)
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
 * InsertTCPOption()
 */
class InsertTCPOption : public BatchElement, TCPHelper {

 public:

  InsertTCPOption() CLICK_COLD;
  ~InsertTCPOption() CLICK_COLD;

  const char *class_name() const		{ return "InsertTCPOption"; }
  const char *port_count() const		{ return "1/1"; }

  int configure(Vector<String> &conf, ErrorHandler *errh) override CLICK_COLD;
  int initialize(ErrorHandler *errh) override CLICK_COLD ;

  void push_batch(int, PacketBatch *) override;


private:

  uint8_t _kind;
  String _value;
};

CLICK_ENDDECLS
#endif
