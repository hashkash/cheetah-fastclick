/*
 * flowcheetahproxy.{cc,hh} -- TCP & UDP load-balancer
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

#include "flowcheetahproxy.hh"

#include <click/config.h>
#include <click/glue.hh>
#include <click/args.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/mpls.h>
#include <click/flow/flow.hh>



CLICK_DECLS

//TODO : disable timer if own_state is false

FlowCheetahProxy::FlowCheetahProxy() : _own_state(true), _accept_nonsyn(true) {

};

FlowCheetahProxy::~FlowCheetahProxy() {

}

int
FlowCheetahProxy::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String mode,lst;
    if (Args(conf, this, errh)
               .read("STATE", _own_state)
               .read("FCB_OFFSET", _flow_data_offset)
               .complete() < 0)
        return -1;


    return 0;
}


int FlowCheetahProxy::initialize(ErrorHandler *errh) {

    return 0;
}


bool FlowCheetahProxy::new_flow(CheetahProxyEntry* flowdata, Packet* p) {
        return true;
}


void FlowCheetahProxy::push_batch(int, CheetahProxyEntry* flowdata, PacketBatch* batch) {

    auto fnt = [this,flowdata](Packet*&p) -> bool {
        WritablePacket* q =p->uniqueify();
        q = q->push(sizeof(mpls_label));
        mpls_label* label = (mpls_label*)q->data();

        label->entry = flowdata->cookie << MPLS_LS_LABEL_SHIFT;
        return true;
    };
    EXECUTE_FOR_EACH_PACKET_UNTIL_DROP(fnt, batch);

    if (batch)
        checked_output_push_batch(0, batch);
}


FlowCheetahProxyReverse::FlowCheetahProxyReverse() : _lb(0) {

};

FlowCheetahProxyReverse::~FlowCheetahProxyReverse() {

}

int
FlowCheetahProxyReverse::configure(Vector<String> &conf, ErrorHandler *errh)
{
    Element* e;
    if (Args(conf, this, errh)
               .read_mp("LB",e)
               .complete() < 0)
        return -1;
    _lb = reinterpret_cast<FlowCheetahProxy*>(e);
    _lb->add_remote_element(this);
    return 0;
}


int FlowCheetahProxyReverse::initialize(ErrorHandler *errh) {
    return 0;
}

void FlowCheetahProxyReverse::push_batch(int, PacketBatch* batch) {

    auto fnt = [this](Packet* &p) -> bool {
        WritablePacket* q =p->uniqueify();
        mpls_label* label = (mpls_label*)q->data();
        uint32_t cookie = label->entry >> MPLS_LS_LABEL_SHIFT;
        q->pull(sizeof(mpls_label));
        //_lb->fcb_data_for(get_context()->get_backward_fcb())->cookie = cookie;
        return true;
    };

    EXECUTE_FOR_EACH_PACKET_UNTIL_DROP(fnt, batch);

    if (batch)
        checked_output_push_batch(0, batch);
}



CLICK_ENDDECLS
EXPORT_ELEMENT(FlowCheetahProxyReverse)
ELEMENT_MT_SAFE(FlowCheetahProxyReverse)
EXPORT_ELEMENT(FlowCheetahProxy)
ELEMENT_MT_SAFE(FlowCheetahProxy)
