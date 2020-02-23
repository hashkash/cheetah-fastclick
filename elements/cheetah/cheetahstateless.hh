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
 * =s tcpudp
 * Cheetah Stateless Load-Balancer
 *
 * =d
 *
 * This element implements the stateless cheetah load balancer. It uses the TCP timestamp to embed a cookie that encodes
 * the server id.
 *
 * The keywords are:
 *
 * =over 8
 *
 * =item BUCKETS
 * Integer. The number of buckets, limiting the amount of servers, and capped by the encoding space of the timestamp field (2^15).
 *
 * =item VIP
 * IP Address. Address of the VIP
 *
 * =item DST
 * List of IP addresses. IPs of the servers.
 *
 * =item HASH
 * Obfuscate the cookie with the hash or not.
 *
 * =item FIX_TS_ECR
 * Fix the timestamp echo field when receiving packets from client, set the original MSB of the server. Needs to be true when not in DSR mode.
 *
 * =item FIX_TS_VAL
 * Fix the value of the TS val when packets come back from client. Set to true if not in DSR mode.
 *
 * =item FIX_IP
 * Fix the IP of the VIP on packets from clients.
 *
 * =item RESET_TIME
 * Sets the time before reseting the values.
 *
 * =item VERBOSE
 * Verbosity level.
 *
 * =item HW
 * Name of the element that receives packets from server, allows to insert flow rules to directly get the server id.
            .
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

  /*
   * Handle packets from clients.
   * For SYN packets, it will:
   * In DSR mode the SYN will have the (maybe encoded) server ID in the TS
   * ECR that should be reflected.
   * Else, it is just forwarded, and handle_from_server does the rest.
   * For other packers:
   * It reads the cookie and fix the original timestamp if not in DSR mode.
   */
  Packet* handle_from_client(Packet *p);

  /*
   * Handle packets from servers. In DSR mode, this acts as
   * IPLoadBalancerReverse, just fixing the source IP. In non-DSR mode
   * the server id is found (using HW flow rules if HW is set to a FromDPDKDevice)
   * and encodes it in the TS. It also write down the current TS MSB of the server
   * for fixing by handle_from_client.
   */
  Packet* handle_from_server(Packet *p);

  void push_batch(int, PacketBatch *);

  void add_handlers() override CLICK_COLD;

  void run_timer(Timer *timer) override;

private:

  /*
   * Verify an idx is in bound
   */
  inline int validate_idx(int b);

  /**
   * Get the server ID from the cookie
   */
  int get_id(tcp_opt_timestamp* ts, WritablePacket* p);

  /*
   * Encodes the server ID in the timestamp
   */
  void set_id(tcp_opt_timestamp* ts, int b, WritablePacket* p);

  static String read_handler(Element *handler, void *user_data);

  static int write_handler(
    const String &, Element *, void *, ErrorHandler *
) CLICK_COLD;


  /**
   * Divides by two the current count of packets, servers and bytes so we do not keep an error from too long
   */
  void clean_counts();
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

  //Per-server buckets
  Vector <CHBucket,CLICK_CACHE_LINE_SIZE> _buckets;

  //Address of the VIP
  IPAddress _vip;

  //Add the hash to the idx
  bool _hash;

#ifdef CHEETAH_COMPLETE
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

  //Maps of IP to servers ids
  HashTable<IPAddress, int> _map;

  //Time between two cleaning of the counters
  int _reset_time;

  //Mask to fast modulo the number of buckets
  unsigned _mask;

  // Hardware classifier for packets from the servers
  DPDKDevice* _hw;

  //Click timer handler
  Timer _timer;

};

CLICK_ENDDECLS
#endif
