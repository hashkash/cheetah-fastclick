#ifndef CLICK_CheetahStateless_HH
#define CLICK_CheetahStateless_HH
#include <click/batchelement.hh>
#include <click/glue.hh>
#include <click/tcphelper.hh>
#include <click/hashtable.hh>
#include <click/loadbalancer.hh>
#include <clicknet/ip.h>
#include <click/timer.hh>

//#define CHEETAH_COMPLETE 1  //Research mode (things that are removed)
#define CHEETAH_EMBED_DST 1 //Keep the DST ip address in the Cheetah Bucket
#define CHEETAH_HW_HASH 1

#include "cheetah.hh"




CLICK_DECLS

class DPDKDevice;

/*
 * =c
 * CheetahStateless(KEYWORD)
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
 * CheetahStateless() -> Print()
 */
class CheetahStateless : public BatchElement, LoadBalancer, Cheetah {

 public:

  CheetahStateless() CLICK_COLD;
  ~CheetahStateless() CLICK_COLD;

  const char *class_name() const		{ return "CheetahStateless"; }
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
#if CHEETAH_EMBED_DST
      IPAddress dst;
#else
	  int dst;
#endif
	  uint32_t last_ts[2];
	  uint8_t version;
  };

  IPAddress _vip;

  //Add the hash to the idx
  bool _hash;

#ifdef CHEETAH_COMPLETE
  //Add the hash to the overall TS_VAL as seen by client
  bool _add_entropy;

  //L2 mode
  bool _l2;

  //Debug
  unsigned _constant_cookie;
#endif


  //If false, server is fixing the timestamp ECR
  bool _fix_ts_ecr;

  //If false, server is setting the TS_VAL for outgoing packets
  bool _set_ts_val;

  //If true (default), the VIP is set back on the IP source. In DSR this should be done by server.
  // In fact in DSR we should not see the packet
  bool _fix_ip;
  int reset_time;
  HashTable<IPAddress, int> _map;
  int _reset_time;
  unsigned _mask;

  DPDKDevice* _hw;

  Vector <CHBucket,CLICK_CACHE_LINE_SIZE> _buckets;

  Timer _timer;

};

CLICK_ENDDECLS
#endif
