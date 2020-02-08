#ifndef CLICK_CheetahStateful_HH
#define CLICK_CheetahStateful_HH
#include <click/batchelement.hh>
#include <click/glue.hh>
#include <click/tcphelper.hh>
#include <click/hashtable.hh>
#include <click/ring.hh>
#include <click/loadbalancer.hh>
#include <click/flow/ctxelement.hh>
#include <click/batchbuilder.hh>
#include <clicknet/ip.h>
#include "cheetah.hh"

CLICK_DECLS

/*
 * =c
 * CheetahStateful(KEYWORD)
 *
 * =s flow
 * Flow/FCB classifier using the cheetah source cookie
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
 * Integer. The number of buckets, limiting the amount of state, and capped by the encoding space of the timestamp field (2^15).
 *
 *
 * =e
 *
 * CheetahStateful() -> Print()
 */

class CheetahStateful : public CTXElement, LoadBalancer, Cheetah, VirtualFlowManager, public Router::InitFuture {

 public:

  CheetahStateful() CLICK_COLD;
  ~CheetahStateful() CLICK_COLD;

  const char *class_name() const		{ return "CheetahStateful"; }
  const char *port_count() const		{ return "1-2/1-2"; }

  void* cast(const char *name) override;

  int configure(Vector<String> &conf, ErrorHandler *errh) override CLICK_COLD;
  int initialize(ErrorHandler *errh) override CLICK_COLD;

  void handle_from_client(Packet *p, BatchBuilder&);
  void handle_from_server(Packet *p, BatchBuilder&);

  void push_batch(int, PacketBatch *) override;

  inline FlowControlBlock* get_opposite_fcb() override;

  int get_id(tcp_opt_timestamp* ts, Packet* p, bool reverse = 0);
  void set_id(tcp_opt_timestamp* ts, int b, WritablePacket* p);


  //Flow bucket
  struct CHBucket {
	  CHBucket() : version(0) {

	  }
	  uint32_t last_ts[2];
	  uint8_t version;
	  FlowControlBlock fcb[0];
  };

  /**
   * One bucket block represents a whole state for a full range of cookies.
   * Then, different blocks are selected according to the packet
   * intrinsincs such as a hash of the 4 tuples.
   */
  class BucketBlock {
  private:
	  BucketBlock() {
		  assert(false);
	  }

  public:
	  BucketBlock(int nbuckets, int flow_state_size_full, int flow_state_bw_size_full);

	  CHBucket *_buckets;
      FlowControlBlock *_backward_fcbs;
	  int _current;
	  Vector<int> _stack;

	  inline int validate_idx(int b);
	  inline int alloc_bucket(const int &_verbose);
	  inline void release_bucket(int b);
  } CLICK_CACHE_ALIGN;

 private:
  inline CHBucket& get_bucket(const BucketBlock* block, const int &b);
  inline FlowControlBlock* get_backward_fcb(const BucketBlock* block, const int &b);


  inline BucketBlock* get_block_for_packet(const Packet* p);

  BucketBlock* _blocks;
  int _nbuckets;
  int _nblocks_mask;

  int _verbose;

  int _backward_reserve;
  int _flow_state_size_full;
  int _flow_state_bw_size_full;
};


extern __thread uint32_t fcb_cookie;
extern __thread CheetahStateful::BucketBlock* fcb_block;

inline FlowControlBlock* CheetahStateful::get_opposite_fcb() {
	  return get_bucket(fcb_block,fcb_cookie).fcb;
}

inline CheetahStateful::CHBucket&
CheetahStateful::get_bucket(const BucketBlock *block, const int &b) {
    return *((CHBucket*)((unsigned char*)block->_buckets + (b * _flow_state_size_full)));
}
inline FlowControlBlock*
CheetahStateful::get_backward_fcb(const BucketBlock *block, const int &b) {
    return ((FlowControlBlock*)((unsigned char*)block->_backward_fcbs + (b * _flow_state_bw_size_full)));
}

inline CheetahStateful::BucketBlock*
CheetahStateful::get_block_for_packet(const Packet* p) {
	return &_blocks[AGGREGATE_ANNO(p) & _nblocks_mask];
}

CLICK_ENDDECLS
#endif
