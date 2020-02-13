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

#include "beamerverifier.hh"

#include <click/config.h>
#include <click/glue.hh>
#include <click/args.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <click/flow/flow.hh>
#include "../beamer/lib/ggencapper.hh"
#include "simplebeamerlb.hh"

CLICK_DECLS

BeamerVerifier::BeamerVerifier() {

};

BeamerVerifier::~BeamerVerifier() {

}

int
BeamerVerifier::configure(Vector<String> &conf, ErrorHandler *errh)
{
    Element* e;
    _dosave = true;
    if (Args(conf, this, errh)
                .read_mp("BEAMER", e)
                .read("SAVE", _dosave)
               .complete() < 0)
        return -1;

    _beamer =(SimpleBeamerLB*) e->cast("SimpleBeamerLB");


    return 0;
}


int BeamerVerifier::initialize(ErrorHandler *errh) {

    return 0;
}


bool BeamerVerifier::new_flow(BeamerVerifierEntry* flowdata, Packet* p) {
    flowdata->dip = ((click_ip*)p->data())->ip_dst;

    //click_chatter("New flow dip %x!", ((click_ip*)p->data())->ip_dst);
    return true;
}


void BeamerVerifier::push_batch(int, BeamerVerifierEntry* flowdata, PacketBatch* batch) {

    auto fnt = [this,flowdata](Packet*&p) -> Packet* {
        WritablePacket* q =p->uniqueify();
        click_ip* encap_ip =  ((click_ip*)p->data());
        click_ip* real_ip = (click_ip*)(p->data() + sizeof(Beamer::IPHeaderWithPrevDIP));
        click_tcp* real_tcp = (click_tcp*)((unsigned char*)real_ip + (real_ip->ip_hl << 2));
        //click_chatter("SYN %d",real_tcp->th_flags & TH_SYN);

        //DIP is the current server destination
        IPAddress dip = encap_ip->ip_dst;
        if (_dosave && dip != flowdata->dip) {
            //If the current server destination is not the first one recorded for the inner flow -> we must redirect to the pdip
            if (unlikely(real_tcp->th_flags & TH_SYN)) {
                flowdata->dip = dip;
            } else {
                Beamer::IPHeaderWithPrevDIP* iph = (Beamer::IPHeaderWithPrevDIP*)p->data();
                uint32_t pdip = iph->opt.pdip;
                //click_chatter("SAVED PDIP %x DIP %x RECORD %x!", pdip, dip, flowdata->dip);
                dip = IPAddress(pdip);
            }
        }

        q->pull(sizeof(Beamer::IPHeaderWithPrevDIP));
        q->set_ip_header((click_ip*)q->data(), (unsigned char*)real_tcp - (unsigned char*) real_ip );
        q->ip_header()->ip_dst = dip;
        q->set_dst_ip_anno(dip);
        return q;
    };
    EXECUTE_FOR_EACH_PACKET_DROPPABLE(fnt, batch, (void));

    if (batch)
        checked_output_push_batch(0, batch);
}


CLICK_ENDDECLS
EXPORT_ELEMENT(BeamerVerifier)
ELEMENT_MT_SAFE(BeamerVerifier)
