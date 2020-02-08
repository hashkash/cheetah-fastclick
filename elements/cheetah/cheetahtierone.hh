#ifndef CLICK_CheetahTierOne_HH
#define CLICK_CheetahTierOne_HH
#include <click/batchelement.hh>
#include <click/glue.hh>
#include <click/tcphelper.hh>
#include <click/hashtable.hh>
#include <click/loadbalancer.hh>
#include <clicknet/ip.h>
#include <click/timer.hh>
#include "cheetah.hh"

CLICK_DECLS

class DPDKDevice;

/*
 * =c
 * CheetahTierOne(KEYWORD)
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
 * =over 8
 *
 * =item BUCKETS
 * Integer. The number of buckets, limiting the amount of servers, and capped by the encoding space of the timestamp field (2^15).
 *
 *
 * =e
 * CheetahTierOne() -> Print()
 */
class CheetahTierOne : public BatchElement, LoadBalancer, Cheetah {

 public:

  CheetahTierOne() CLICK_COLD;
  ~CheetahTierOne() CLICK_COLD;

  const char *class_name() const		{ return "CheetahTierOne"; }
  const char *port_count() const		{ return "2/2"; }

  int configure(Vector<String> &conf, ErrorHandler *errh) CLICK_COLD;
  int initialize(ErrorHandler *errh) CLICK_COLD;

  Packet* handle_from_client(Packet *p);
  Packet* handle_from_server(Packet *p);

  void push_batch(int, PacketBatch *);

  void add_handlers() override CLICK_COLD;

private:
  inline int validate_idx(int b);
  int get_id(tcp_opt_timestamp* ts, WritablePacket* p);
  void set_id(tcp_opt_timestamp* ts, int b, WritablePacket* p);
  static String read_handler(Element *handler, void *user_data);
  void run_timer(Timer *timer);
  void clean_counts();
  static int write_handler(
    const String &, Element *, void *, ErrorHandler *
) CLICK_COLD;


  struct CHBucket {
	  CHBucket() : dst(-1), version(0) {

	  }
	  int dst;
	  uint32_t last_ts[2];
	  uint8_t version;
  };


  //If true (default), the VIP is set back on the IP source. In DSR this should be done by server.
  // In fact in DSR we should not see the packet
  int _reset_time;
  unsigned _tier_bits;


  Vector <CHBucket> _buckets;


  Timer _timer;

};

CLICK_ENDDECLS
#endif
