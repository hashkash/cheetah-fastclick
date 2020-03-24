// -*- c-basic-offset: 4; related-file-name: "../include/click/cheetahstateless.hh"-*-
/*
 * cheetahstateless.{cc,hh} -- element
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
#include "cheetahstateless.hh"
#include "cheetah.hh"
#include <rte_flow.h>
#include <immintrin.h>


CLICK_DECLS

CheetahStateless::CheetahStateless() :
    _hw(0),
    _timer(this)
{
}

CheetahStateless::~CheetahStateless()
{
}

int
CheetahStateless::configure(Vector<String> &conf, ErrorHandler *errh)
{
    int nbuckets = 0;
    String lb_mode;
    String lst_mode;
    bool has_fix_ip;
    Element* hw = 0;
    if (Args(this, errh).bind(conf)
            .read_or_set_p("BUCKETS", nbuckets, 256)
            .read_mp("VIP", _vip)
            .read_all("DST", _dsts)
            .read_or_set("HASH", _hash, false)
            .read_or_set("FIX_TS_ECR", _fix_ts_ecr, false)
            .read_or_set("SET_TS_VAL", _set_ts_val, true)
            .read_or_set("FIX_IP", _fix_ip, true).read_status(has_fix_ip)
            .read_or_set("VERBOSE", _verbose, 0)
            .read_or_set("RESET_TIME",_reset_time,-1)
#ifdef CHEETAH_COMPLETE
            .read_or_set("L2", _l2, false)
#endif
            .read("HW", hw)
            .consume() < 0)

        return -1;

    if (parseLb(conf, this, errh) < 0)
        return -1;

    if (Args(this, errh).bind(conf).complete() < 0)
        return -1;

    _buckets.resize(nbuckets);

    _mask = nbuckets - 1;

#ifdef CHEETAH_COMPLETE
    if (has_fix_ip &&
            _l2 &&
            _fix_ip) {
        return errh->error("Cannot fix IP address but stay in L2 mode");
    }

    if (_l2)
        _fix_ip = true;
#endif

    for (int i = 0; i < _dsts.size(); i++) {
#if CHEETAH_EMBED_DST
        _buckets[i].dst = _dsts[i];
#else
        _buckets[i].dst = i;
#endif
        _map.find_insert(_dsts[i],i);
    }

    if (_reset_time > 0) {
        _timer.initialize(this);
        _timer.schedule_after_sec(_reset_time);
    }

    if (hw != 0) {
        _hw = (DPDKDevice*)hw->cast("DPDKDevice");
        if (!_hw) {
            return errh->error("HW is not a FromDPDKDevice");
        }
    }

#if CHEETAH_HW_HASH
    if (_hash)
        click_chatter("Wargning : in HW hash mode, hash must be symmetric even with different DST ip (left) and SRC ip (right)!");
#endif
    return 0;
}

void
CheetahStateless::run_timer(Timer *timer)
{
    // Expire any old entries, and make sure there's room for at least one
    // packet.
    if (_track_load)
        clean_counts();

    timer->reschedule_after_sec(_reset_time);
}

void
CheetahStateless::clean_counts()
{
    for (int i = 0; i < _dsts.size(); i++) {
        _loads[i].connection_load = _loads[i].connection_load * 0.6;
        _loads[i].packets_load = _loads[i].packets_load * 0.6;
        _loads[i].bytes_load = _loads[i].packets_load * 0.6;
    }
}

int
CheetahStateless::initialize(ErrorHandler *errh)
{
    if (_track_load)
        click_chatter("Load tracking is ON");

    //Set rules if HW mode is on
    if (_hw != 0) {
        struct rte_flow_attr attr;
        struct rte_flow_action action[3];
        struct rte_flow_action_mark mark;
        struct rte_flow_action_rss rss;
        int port_id = _hw->port_id;
        for (int i = 0; i < _dsts.size(); i++) {
            /*
             * set the rule attribute.
             * in this case only ingress packets will be checked.
             */
            memset(&attr, 0, sizeof(struct rte_flow_attr));
            attr.ingress = 1;

            memset(action, 0, sizeof(action));
            memset(&rss, 0, sizeof(rss));

            action[0].type = RTE_FLOW_ACTION_TYPE_MARK;
            mark.id = i;
            action[0].conf = &mark;
            action[1].type = RTE_FLOW_ACTION_TYPE_RSS;
            uint16_t queue[RTE_MAX_QUEUES_PER_PORT];
            auto threads = get_passing_threads();
            for (int i = 0; i < _hw->nbRXQueues(); i++) {
                queue[i] = i;
            }
            uint8_t rss_key[40];
            struct rte_eth_rss_conf rss_conf;
            rss_conf.rss_key = rss_key;
            rss_conf.rss_key_len = 40;
            rte_eth_dev_rss_hash_conf_get(port_id, &rss_conf);
            rss.types = rss_conf.rss_hf;
            rss.key_len = rss_conf.rss_key_len;
            rss.queue_num = _hw->nbRXQueues();
            rss.key = rss_key;
            rss.queue = queue;
            rss.level = 0;
            rss.func = RTE_ETH_HASH_FUNCTION_DEFAULT;
            action[1].conf = &rss;

            action[2].type = RTE_FLOW_ACTION_TYPE_END;

            Vector<rte_flow_item> pattern;

            rte_flow_item pat;
            pat.type = RTE_FLOW_ITEM_TYPE_IPV4;

            struct rte_flow_item_ipv4* spec = (struct rte_flow_item_ipv4*) malloc(sizeof(rte_flow_item_ipv4));
            struct rte_flow_item_ipv4* mask = (struct rte_flow_item_ipv4*) malloc(sizeof(rte_flow_item_ipv4));
            bzero(spec, sizeof(rte_flow_item_ipv4));
            bzero(mask, sizeof(rte_flow_item_ipv4));
            pat.spec = spec;
            pat.mask = mask;
            pat.last = 0;
            spec->hdr.src_addr = _dsts[i];
            mask->hdr.src_addr = IPAddress::make_broadcast();
            pattern.push_back(pat);

            rte_flow_item end;
            memset(&end, 0, sizeof(struct rte_flow_item));
            end.type =  RTE_FLOW_ITEM_TYPE_END;
            pattern.push_back(end);

            struct rte_flow_error error;
            int res;
            res = rte_flow_validate(port_id, &attr, pattern.data(), action, &error);
            const char* actiont = "mark";
            if (!res) {
                struct rte_flow *flow = rte_flow_create(port_id, &attr, pattern.data(), action, &error);
                if (flow) {
                    click_chatter("Flow added succesfully with %d patterns to id %d with action %s !", pattern.size(), i, actiont);
                } else {

                    click_chatter("Could not add pattern with %d patterns with action %s, error %d : %s", pattern.size(), actiont, res, error.message);
                }
            } else {
                click_chatter("Could not validate pattern with %d patterns with action %s, error %d : %s", pattern.size(), actiont,  res, error.message);
            }
        }
    }

    
    return 0;
}

inline int CheetahStateless::validate_idx(int b) {
    return !(b >= _buckets.size()
#if CHEETAH_EMBED_DST
#else
            || _buckets.unchecked_at(b).dst == -1
#endif
            );
}

int CheetahStateless::get_id(tcp_opt_timestamp* ts, WritablePacket* p) {
    // Cookie is in the echo request
    int b = ntohl(ts->ts_ecr);

    // Extract cookie from the TS
    int idx = TS_GET_COOKIE(b);

#ifdef CHEETAH_COMPLETE
    // Just debugging stuffs
    if (unlikely(_verbose > 2)) {
        click_chatter("Got idx %d", idx);
        if (_hash) {
            click_chatter("Hash is %u", hash(p,false));
            click_chatter("Unparsed is %u", hash(p,false) ^ idx);
        }
    }
#endif

    //If cookie obfuscation is enabled
    if (_hash) {
        idx = (hash(p,false) ^  idx) % _buckets.size();
    }

    // Check the index is valid
    if (unlikely(!validate_idx(idx))) {
        return -1;
    }

    // Fix the timestamp MSB bits so the server gets the correct value
    if (_fix_ts_ecr) {
#ifdef COOKIE_MSB
        int val = TS_GET_LSB(b) | _buckets[idx].last_ts[TS_GET_VERSION(b)];
#else
        int val = (b >> TS_VAL_SHIFT) | (_buckets[idx].last_ts[TS_GET_VERSION(b)] << TS_VAL_SHIFT);
#endif
        rewrite_ts(p, ts, 1, htonl(val));
    }
    return idx & _mask;
}

void CheetahStateless::set_id(tcp_opt_timestamp* ts, int b, WritablePacket* p) {
    // Get the server id
    int rand_offset = b & _mask;

    // If obfuscation is enabled, xor the cookie
    if (_hash) {
#ifdef CHEETAH_COMPLETE
        //eg b is 3, hash is 938
        // rand_offset = 3 - 938 == -935 == 64601
        // computed offset will be 938 + 64601 = 65539 % 256 = 3
        if (unlikely(_verbose > 1)) {

            click_chatter("Offset is %u", rand_offset);
            click_chatter("Hash is %u", hash(p,true));
            click_chatter("Unparsed is %u", find_rand_offset(b,hash(p,true)));
        }
#endif
        rand_offset = find_rand_offset(b,hash(p,true));
    }

    // Get TS val
    int val = ntohl(ts->ts_val);

    // Put the cookie in the ECR
    if (_fix_ts_ecr) {
    #ifdef COOKIE_MSB
        uint32_t msb = val & ~TS_LSB_MASK;

        int version = _buckets[b].version;

#ifdef CHEETAH_COMPLETE
        if (unlikely(_verbose > 3)) {
                click_chatter("[Bucket #%d] Set MSB %d (LSB is %d)!",b, msb, TS_GET_LSB(val));
        }
#endif

        if (_buckets[b].last_ts[version] != msb) {
            version = 1 - version;

#ifdef CHEETAH_COMPLETE
            if (unlikely(_verbose)) {
                click_chatter("[Bucket #%d] New version %d!",b, version);
            }
#endif
            _buckets[b].last_ts[version] = msb;

            _buckets[b].version = version;
        }
        rand_offset = (rand_offset & TS_SHIFTED_VAL_MASK ) | (version << TS_VERSION_BIT);
#else
        //VAL comes from server, has
        // [ ---  MSB ----] [ V / LSB ]

        uint16_t msb = TS_GET_MSB(val);
        unsigned v = val >> 15 & 0x1;
        if (_buckets[b].last_ts[v] != msb)
            _buckets[b].last_ts[v] = msb;
#endif
    }

#ifdef COOKIE_MSB
    val = (val & TS_LSB_MASK) | (rand_offset << TS_SHIFT);
#else
    // becomes [V / LSB][ COOKIE ]
    val = (rand_offset & TS_COOKIE_MASK) | (TS_GET_MSB(val) << TS_VAL_SHIFT);
#endif

    rewrite_ts(p, ts, 0, htonl(val));
}

int
CheetahStateless::write_handler(
        const String &input, Element *e, void *thunk, ErrorHandler *errh) {
    CheetahStateless *cs = static_cast<CheetahStateless *>(e);

    return cs->lb_write_handler(input,thunk,errh);
}

String
CheetahStateless::read_handler(Element *e, void *thunk) {
    CheetahStateless *cs = static_cast<CheetahStateless *>(e);
    return cs->lb_read_handler(thunk);
}

void
CheetahStateless::add_handlers(){
    add_write_handler("load", write_handler, h_load);
    add_read_handler("load", read_handler, h_load);
    add_read_handler("nb_active_servers", read_handler, h_nb_active_servers);
    add_read_handler("nb_total_servers", read_handler, h_nb_total_servers);
    add_read_handler("load_conn", read_handler, h_load_conn);
    add_read_handler("load_bytes", read_handler, h_load_bytes);
    add_read_handler("load_packets", read_handler, h_load_packets);
    add_write_handler("remove_server", write_handler, h_remove_server);
    add_write_handler("add_server", write_handler, h_add_server);
}

Packet *
CheetahStateless::handle_from_client(Packet *p_in)
{
    WritablePacket* p = p_in->uniqueify();

    tcp_opt_timestamp* ts = parse_ts_from_client(p);

    if (likely(ts)) {
        if (unlikely(_verbose > 2))
            click_chatter("From client: OPT found!");
    } else {
        if (_verbose > 0) {
            click_chatter("From client: OPT not found! Dropping packet.");
            if (isRst(p)) {
                click_chatter("(The packet was a RST (%s))", IPFlowID(p).unparse().c_str());
            }
        }
        p->kill();
        return 0;
    }

    int b;
    if (isSyn(p)) {
       /* if (!ts) {
            click_chatter("SYN without TS option!");
            p->kill();
            return 0;
        } else*/ {
            //Allocate bucket

            b = pick_server(p);

            //b = 0;
            if (_track_load)
                _loads[b].connection_load++;

#ifdef CHEETAH_COMPLETE
            if (unlikely(_verbose > 1)) {
                click_chatter("New connection with bucket %d", b);
                click_chatter("==================Now the connection load of this bucket is %d=================",_loads[b].connection_load);
            }
#endif

            if (_fix_ts_ecr) {
                //No need to compute the offset with hash() has here we only find a new assignment
                //The cookie will be set when we receive the packet back
            } else {
                int rand_offset = b;
                if (_hash)
                    rand_offset = find_rand_offset(b, hash(p,false));

                //No need to set the version when _fix_ts_ecr is not set

                //Set the offset in ECR (0 for a SYN)
                int val = 0 | (rand_offset << TS_SHIFT);

#ifdef CHEETAH_COMPLETE
                if (unlikely(_verbose > 2))
                    click_chatter("TS %x, offset %d, rand %d", val, b, rand_offset);
#endif
                rewrite_ts(p, ts, 1, htonl(val));
            }
        }
    } else {

        b = get_id(ts, p);        //Get and fix id
        if (_track_load) {
            _loads[b].packets_load++;
            _loads[b].bytes_load += p->length();
        }

#ifdef CHEETAH_COMPLETE
        if (unlikely(_verbose > 3)) {
            for(int i = 0; i <_dsts.size();i++){
            click_chatter("Packest with server %d is %d", i, _loads[i].packets_load);
            click_chatter("Bytes with server %d is %d",i, _loads[i].bytes_load);
            }
        }
#endif

        if (unlikely(_track_load && isFin(p))) {
            _loads[b].connection_load--;
            if (_verbose > 1) {
                click_chatter("Connection end in bucket %d", b);
                click_chatter("********************Now the connection load of this bucket is %d*******************",_loads[b].connection_load);
            }
        }
    }

    if (unlikely(b == -1)) {
        click_chatter("Bad destination");
        p->kill();
        return 0;
    }

#ifdef CHEETAH_COMPLETE
    if (unlikely(_verbose > 2))
        click_chatter("Packet from client with bucket %d, hash %x", b, AGGREGATE_ANNO(p));
#endif
    auto &bucket = _buckets.unchecked_at(b);
#if CHEETAH_EMBED_DST
    auto &dst = bucket.dst;
#else
    auto &dst = _dsts.unchecked_at(bucket.dst);
#endif
#ifdef CHEETAH_COMPLETE
    if (!_l2)
#endif
        p->ip_header()->ip_dst = dst;
    p->set_dst_ip_anno(dst);

    return p;
}

Packet *
CheetahStateless::handle_from_server(Packet *p_in)
{
    WritablePacket* p;

#ifdef CHEETAH_COMPLETE
    if (unlikely(_verbose > 2))
        click_chatter("Packet from server, hash %x", AGGREGATE_ANNO(p_in));
#endif

    if (!isRst(p_in) && _set_ts_val) { //If SET_TS_VAL is false, then server is already setting TS_VAL
        p = p_in->uniqueify();

        tcp_opt_timestamp* ts = parse_ts_from_server(p);
        if (likely(ts)) {
            if (unlikely(_verbose > 2))
                click_chatter("From server: OPT found!");
        } else {
            click_chatter("From server: OPT not found! Dropping packet.");
            p->kill();
            return 0;
        }

        int b = -1;;
        if (likely(_hw)) {
            rte_mbuf* mbuf = (rte_mbuf*)p->destructor_argument();
            if (likely(mbuf->ol_flags & PKT_RX_FDIR_ID)) {
                b = mbuf->hash.fdir.hi;
            }
        }
        if (unlikely(b == -1)) {
            auto it = _map.find(p->ip_header()->ip_src);
            if (!it) {
                click_chatter("WARNING : unknown source IP %s. Dropping packet. The LB is probably reversed.", IPAddress(p->ip_header()->ip_src).unparse().c_str());
                p->kill();
                return 0;
            }
            b = it.value();
        }
        set_id(ts, b, p);
    } else if (_fix_ip) {
        p = p_in->uniqueify();
    } else {
        return p_in;
    }

    if (_fix_ip) { //If DSR is enabled, the IP is already fixed by the server
        p->ip_header()->ip_src = _vip;
    }

    return p;
}

void
CheetahStateless::push_batch(int port, PacketBatch *batch)
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
EXPORT_ELEMENT(CheetahStateless)
//ELEMENT_MT_SAFE(CheetahStateless) //Think carefully!
