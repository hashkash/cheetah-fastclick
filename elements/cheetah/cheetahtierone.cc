// -*- c-basic-offset: 4; related-file-name: "../include/click/CheetahTierOne.hh"-*-
/*
 * CheetahTierOne.{cc,hh} -- element
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
#include <click/straccum.hh>
#include <click/args.hh>
#include <click/ipflowid.hh>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include "cheetahtierone.hh"
#include "cheetah.hh"
#include <rte_flow.h>
#include <immintrin.h>


CLICK_DECLS

CheetahTierOne::CheetahTierOne() : _timer(this)
{
}

CheetahTierOne::~CheetahTierOne()
{
}

int
CheetahTierOne::configure(Vector<String> &conf, ErrorHandler *errh)
{
    int nbuckets = 0;
    bool has_fix_ip;
    Element* hw = 0;
    int tb = 2;
    if (Args(this, errh).bind(conf)
		.read_or_set_p("TIER_BITS", tb, 2)
            .read_or_set_p("BUCKETS", nbuckets, 4)
            .read_all("DST", _dsts)
            .read_or_set("VERBOSE", _verbose, 0)
            .read_or_set("RESET_TIME",_reset_time,-1)
            .consume() < 0)

        return -1;
    if (parseLb(conf, this, errh) < 0)
	    return -1;
    if (Args(this, errh).bind(conf).consume() < 0)
	return -1;

    _tier_bits = TS_BITS - tb;

    _buckets.resize(nbuckets);



    for (int i = 0; i < _dsts.size(); i++) {
        _buckets[i].dst = i;
    }

    if (_reset_time > 0) {
        _timer.initialize(this);
        _timer.schedule_after_sec(_reset_time);
    }


    return 0;
}

void
CheetahTierOne::run_timer(Timer *timer)
{
    // Expire any old entries, and make sure there's room for at least one
    // packet.
    if (_track_load)
        clean_counts();

    timer->reschedule_after_sec(_reset_time);
}

void
CheetahTierOne::clean_counts()
{
    for (int i = 0; i < _dsts.size(); i++) {
        _loads[i].connection_load = _loads[i].connection_load * 0.6;
        _loads[i].packets_load = _loads[i].packets_load * 0.6;
        _loads[i].bytes_load = _loads[i].packets_load * 0.6;
    }
}

int
CheetahTierOne::initialize(ErrorHandler *errh)
{
    if (_track_load)
        click_chatter("Load tracking is ON");

    _loads.resize(_dsts.size());
    CLICK_ASSERT_ALIGNED(_loads.data());
    return 0;
}

inline int CheetahTierOne::validate_idx(int b) {
    return !(b >= _buckets.size() || _buckets[b].dst == -1);
}

int CheetahTierOne::get_id(tcp_opt_timestamp* ts, WritablePacket* p) {
    int b = ntohl(ts->ts_ecr);

    int idx = TS_GET_COOKIE(b) >> _tier_bits;
    if (unlikely(_verbose > 2)) {
        click_chatter("Got idx %d", idx);
    }

    return idx;
}




enum {
        h_load,h_nb_total_servers,h_nb_active_servers,h_load_conn,h_load_packets,h_load_bytes
};



int
CheetahTierOne::write_handler(
        const String &input, Element *e, void *thunk, ErrorHandler *errh) {
    CheetahTierOne *cs = static_cast<CheetahTierOne *>(e);

    switch((uintptr_t) thunk) {
        case h_load: {
            String s(input);
            //click_chatter("Input %s", s.c_str());
            while (s.length() > 0) {
                int ntoken = s.find_left(',');
                if (ntoken < 0)
                    ntoken = s.length() - 1;
                int pos = s.find_left(':');
                int server_id = atoi(s.substring(0,pos).c_str());
                int server_load = atoi(s.substring(pos + 1, ntoken).c_str());
                //click_chatter("%d is %d",server_id, server_load);
                cs->_loads[server_id].cpu_load = server_load;
                s = s.substring(ntoken + 1);
            }
            if (cs->_autoscale)
		cs->checkload();
            return 0;
        }
    }
    return -1;
}

String
CheetahTierOne::read_handler(Element *e, void *thunk) {
    CheetahTierOne *cs = static_cast<CheetahTierOne *>(e);

    switch((uintptr_t) thunk) {
        case h_load: {
            StringAccum acc;
            for (int i = 0; i < cs->_dsts.size(); i ++) {
                acc << cs->_loads[i].cpu_load << (i == cs->_dsts.size() -1?"":" ");
            }
            return acc.take_string();
        }
        case h_nb_active_servers: {
		return String(cs->_selector.size());
        }
        case h_nb_total_servers: {
			return String(cs->_dsts.size());
		}
        case h_load_conn: {
            StringAccum acc;
            for (int i = 0; i < cs->_dsts.size(); i ++) {
                acc << cs->get_load_metric(i,connections) << (i == cs->_dsts.size() -1?"":" ");
            }
            return acc.take_string();}
        case h_load_packets:{
            StringAccum acc;
            for (int i = 0; i < cs->_dsts.size(); i ++) {
                acc << cs->get_load_metric(i,packets) << (i == cs->_dsts.size() -1?"":" ");
            }
            return acc.take_string();}
        case h_load_bytes:{
            StringAccum acc;
            for (int i = 0; i <cs-> _dsts.size(); i ++) {
                acc << cs->get_load_metric(i,bytes) << (i == cs->_dsts.size() -1?"":" ");
            }
            return acc.take_string();}
        default:
		return "<none>";
    }
}


void
CheetahTierOne::add_handlers(){
    add_write_handler("load", write_handler, h_load);
    add_read_handler("load", read_handler, h_load);
    add_read_handler("nb_active_servers", read_handler, h_nb_active_servers);
    add_read_handler("nb_total_servers", read_handler, h_nb_total_servers);
    add_read_handler("load_conn", read_handler, h_load_conn);
    add_read_handler("load_bytes", read_handler, h_load_bytes);
    add_read_handler("load_packets", read_handler, h_load_packets);
}



Packet *
CheetahTierOne::handle_from_client(Packet *p_in)
{
    WritablePacket* p = p_in->uniqueify();

    tcp_opt_timestamp* ts = parse_ts_from_client(p);
    unsigned b;

    if (likely(ts)) {
        if (unlikely(_verbose > 2))
            click_chatter("From client: OPT found!");


		int b;
		if (isSyn(p)) {

				//Allocate bucket


				b = pick_server(p);

				//b = 0;
				if (_track_load)
					_loads[b].connection_load++;

				if (unlikely(_verbose > 1)) {
					click_chatter("New connection with bucket %d", b);
					click_chatter("==================Now the connection load of this bucket is %d=================",_loads[b].connection_load);
				}



		} else { //Not SYN

			b = get_id(ts, p);        //Get and fix id
			if (_track_load) {
				_loads[b].packets_load++;
				_loads[b].bytes_load += p->length();
			}
			if (unlikely(_verbose > 3)) {
				for(int i = 0; i <_dsts.size();i++){
				click_chatter("Packest with server %d is %d", i, _loads[i].packets_load);
				click_chatter("Bytes with server %d is %d",i, _loads[i].bytes_load);
				}
			}

			if (unlikely(_track_load && isFin(p))) {
				_loads[b].connection_load--;
				if (_verbose > 1) {
					click_chatter("Connection end in bucket %d", b);
					click_chatter("********************Now the connection load of this bucket is %d*******************",_loads[b].connection_load);
				}
			}
		}
    } else { //No TS. Just hash
	unsigned server_val = AGGREGATE_ANNO(p);
		server_val = ((server_val >> 16) ^ (server_val & 65535)) % _selector.size();
		b =  _selector[server_val];
    }

    if (unlikely(b == -1)) {
        click_chatter("Bad destination");
        p->kill();
        return 0;
    }

    if (unlikely(_verbose > 2))
        click_chatter("Packet from client with bucket %d", b);

    auto &bucket = _buckets.unchecked_at(b);
    auto &dst = _dsts.unchecked_at(bucket.dst);

    p->set_dst_ip_anno(dst);

    return p;
}

Packet *
CheetahTierOne::handle_from_server(Packet *p_in)
{

        return p_in;
}

void
CheetahTierOne::push_batch(int port, PacketBatch *batch)
{
    if (port == 0) {
        EXECUTE_FOR_EACH_PACKET_DROPPABLE(handle_from_client, batch, (void));
    } else {
        EXECUTE_FOR_EACH_PACKET_DROPPABLE(handle_from_server, batch, (void));
    }
    if (batch)
        output_push_batch(port, batch);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(CheetahTierOne)
ELEMENT_MT_SAFE(CheetahTierOne)
