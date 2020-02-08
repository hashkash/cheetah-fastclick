// -*- c-basic-offset: 4; related-file-name: "../include/click/CheetahStateful.hh"-*-
/*
 * CheetahStateful.{cc,hh} -- element
 * Tom Barbette
 *
 * Copyright (c) 2019 KTH Royal Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include <click/error.hh>
#include <click/args.hh>
#include <click/ipflowid.hh>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include "cheetahstateful.hh"
#include "cheetah.hh"


CLICK_DECLS

__thread uint32_t fcb_cookie = 0;
__thread CheetahStateful::BucketBlock* fcb_block;


CheetahStateful::CheetahStateful() : _blocks(0), _nbuckets(0), _nblocks_mask(0),
    _verbose(0), _backward_reserve(0), _flow_state_size_full(0),
    _flow_state_bw_size_full(0)
{
}

CheetahStateful::~CheetahStateful()
{
}

int
CheetahStateful::configure(Vector<String> &conf, ErrorHandler *errh)
{
	int nbuckets = 32768;
	int nblocks;
	//Vector<IPAddress> dsts;
	if (Args(conf, this, errh)
			.read_or_set_p("BLOCKS", nblocks, 256)
			.read_or_set("VERBOSE", _verbose, 0)
			.read_or_set("RESERVE", _reserve, 0)
			.read_or_set("BACKWARD_RESERVE", _backward_reserve, 0)

			.complete() < 0)
		return -1;

    find_children(this, _verbose);

    router()->get_root_init_future()->postOnce(&_fcb_builded_init_future);
    _fcb_builded_init_future.post(this);

	_flow_state_size_full = sizeof(FlowControlBlock) + _reserve + sizeof(CHBucket);
    if (_backward_reserve >= 0)
	_flow_state_bw_size_full = sizeof(FlowControlBlock) + _backward_reserve;

	if (!is_pow2(nblocks)) {
		return errh->error("nblocks must be pow2");
	}

	_nbuckets = nbuckets;
	_nblocks_mask = nblocks - 1;

    if (ninputs() > 1)
        click_chatter("The RSS hash function must be symmetric !");

	return 0;
}

void*
CheetahStateful::cast(const char *name) {
    if (strcmp(name,"VirtualFlowManager") == 0)
        return dynamic_cast<VirtualFlowManager*>(this);
    return FlowElement::cast(name);
}



int
CheetahStateful::initialize(ErrorHandler *errh)
{
	buildFunctionStack();

	_blocks = (BucketBlock*)CLICK_ALIGNED_ALLOC(sizeof(BucketBlock) * (_nblocks_mask + 1));
	for (int i = 0; i < _nblocks_mask + 1; i++) {
		new(&_blocks[i]) BucketBlock(_nbuckets,_flow_state_size_full,_flow_state_bw_size_full);
	}
	return 0;
}

inline int hash(const Packet* p, const bool reverse = false) {
	return IPFlowID(p, reverse).hashcode() & ((1 << 16) - 1);
}


inline int CheetahStateful::BucketBlock::validate_idx(int b) {
	return !(b >= _stack.size());// || _buckets[b].dst == -1);
}

inline int CheetahStateful::get_id(tcp_opt_timestamp* ts, Packet* p, bool reverse) {
    int b = ntohl(reverse? ts->ts_val : ts->ts_ecr);

	int idx = TS_GET_COOKIE(b);
    if (unlikely(_verbose > 2)) {
        click_chatter("Got idx %d", idx);
    }
/*
	if (!validate_idx(idx)) {
		return -1;
	}*/
	return idx;
}

//b is always the real bucket id
void CheetahStateful::set_id(tcp_opt_timestamp* ts, int b, WritablePacket* p) {
	int rand_offset = b;

	int val = ntohl(ts->ts_val);
#if COOKIE_MSB
	val = (val & TS_LSB_MASK) | (rand_offset << TS_SHIFT);
#else
	val = (val << TS_VAL_SHIFT) | (rand_offset & TS_COOKIE_MASK);
#endif
	rewrite_ts(p, ts, 0, htonl(val));

}

inline int
CheetahStateful::BucketBlock::alloc_bucket(const int &_verbose) {
	int b;
	/*if (_atomic) {
		b = _stack.pop_ret_atomic();
	} else {
		b = _stack.pop_ret();
	}*/
    if (_verbose > 1)
        click_chatter("Alloc current %u", _current);
	if (_current > 0) {
		b = _stack.unchecked_at(_current);
		_current--;
		return b;
	}
	else
		return -1;
}

inline void
CheetahStateful::BucketBlock::release_bucket(int b) {
	/*if (_atomic) {
		b = _stack.push_atomic(b);
	} else {
		b = _stack.push(b);
	}*/
	_stack[_current] = b;
	_current += 1;
}

CheetahStateful::BucketBlock::BucketBlock(int nbuckets, int flow_state_size_full, int flow_state_bw_size_full) :  _current(0) {
	_stack.resize(nbuckets);

	size_t sz =  flow_state_size_full * nbuckets;
	_buckets = (CHBucket*)CLICK_ALIGNED_ALLOC(sz);
	bzero(_buckets, sz);

	for (int i = 0; i < nbuckets; i++) {
		_stack[i] = i;
		//_buckets[i].dst = i;
	}
    _current = nbuckets - 1;

    if (flow_state_bw_size_full > 0) {
        sz = flow_state_bw_size_full * nbuckets;
	_backward_fcbs = (FlowControlBlock*)CLICK_ALIGNED_ALLOC(sz);
	bzero(_backward_fcbs, sz);
    }
}

void
CheetahStateful::handle_from_client(Packet *p_in, BatchBuilder &builder)
{
	//Find the timestamp options

	WritablePacket* p = p_in->uniqueify();


	tcp_opt_timestamp* ts = parse_ts_from_client(p);

	//If we don't find the TS, we drop. A more realistic experiment would send the packet to a backward compatible path
	if (likely(ts)) {
		if (unlikely(_verbose > 2))
			click_chatter("From client: OPT found!");
	} else {
        if (_verbose > 0) {
            click_chatter("From client: OPT not found! Dropping packet.");
            if (isRst(p)) {
                click_chatter("(The packet was a RST)");
            }
        }
        p->kill();
        return;
	}

	BucketBlock *block = get_block_for_packet(p);
	int b;
	if (isSyn(p)) {
			//Allocate bucket
			b = block->alloc_bucket(_verbose);

			//Verify we actually got one
            if (unlikely(b < 0)) {
                click_chatter("No more buckets for block %u (0/%u)!",  ((unsigned char*)_blocks - (unsigned char*)block) / sizeof(BucketBlock), _nblocks_mask + 1);
                p->kill();
                return;
            }

            if (unlikely(_verbose > 1))
                click_chatter("New connection with bucket %d on block %d", b, ((unsigned char*)_blocks - (unsigned char*)block) / sizeof(BucketBlock));


            //Set the offset in ECR (0 for a SYN)
            int val = 0 | (b << TS_SHIFT);

            if (unlikely(_verbose > 2))
                click_chatter("TS %x, offset %d", val, b);

            rewrite_ts(p, ts, 1, htonl(val));
	} else {
		//Get and fix id
		b = get_id(ts, p);

		if (unlikely(b == -1)) {
			click_chatter("Bad destination");
			p->kill();
			return;
		}
	}


	if (unlikely(_verbose > 2))
		click_chatter("Packet from client with bucket %d, S%dA%dR%d", b,isSyn(p),isAck(p),isRst(p));

	if (builder.last == b) {
		builder.append(p);
	} else {
		PacketBatch* batch;
		batch = builder.finish();
		if (batch)
			output_push_batch(0, batch);
		fcb_block = block;
		fcb_cookie = b;
		fcb_stack = get_bucket(block,b).fcb;
        if (_verbose > 2)
            click_chatter("FCB %p", fcb_stack);
		builder.init();
        builder.append(p);
	}
}

void
CheetahStateful::handle_from_server(Packet *p, BatchBuilder& builder)
{
	//Find the timestamp options
	tcp_opt_timestamp* ts = parse_ts_from_server(p);

	//Kill packet if not TS
	if (likely(ts)) {
		if (_verbose > 2)
			click_chatter("From server: OPT found!");
	} else {
        if (_verbose > 0) {
            click_chatter("From server: OPT not found! Dropping packet.");
            if (isRst(p)) {
                click_chatter("(The packet was a RST)");
            }
            p->kill();
        }
        return;
	}

	//Find id, it should be in the VAL
	int b = get_id(ts, p, true);

	BucketBlock *block = get_block_for_packet(p);

	if (builder.last == b) {
		builder.append(p);
	} else {
		PacketBatch* batch;
		batch = builder.finish();
		if (batch)
			output_push_batch(1, batch);
		fcb_block = block;
		fcb_cookie = b;
		fcb_stack = get_backward_fcb(block,b);
        if (_verbose > 2)
            click_chatter("BACKWARD FCB %p", fcb_stack);
		builder.init();
        builder.append(p);
	}
}


/**
 * Main processing funtions. Port 0 is from client, port 1 from server.
 */
void CheetahStateful::push_batch(int port, PacketBatch* batch) {
	BatchBuilder b;

	if (port == 0) {
		FOR_EACH_PACKET_SAFE(batch, p) {
			handle_from_client(p, b);
		}
	} else {
		FOR_EACH_PACKET_SAFE(batch, p) {
			handle_from_server(p, b);
		}
	}

	batch = b.finish();
	if (batch)
		output_push_batch(port, batch);

}


CLICK_ENDDECLS
EXPORT_ELEMENT(CheetahStateful)
//ELEMENT_MT_SAFE(CheetahStateful) //Think carefully!
