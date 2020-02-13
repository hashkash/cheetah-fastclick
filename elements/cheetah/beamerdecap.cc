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


#include <click/config.h>
#include <click/glue.hh>
#include <click/args.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include "../beamer/lib/ggencapper.hh"

#include "beamerdecap.hh"
CLICK_DECLS

BeamerDecap::BeamerDecap() {

};

BeamerDecap::~BeamerDecap() {

}

int
BeamerDecap::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (Args(conf, this, errh)
               .complete() < 0)
        return -1;



    return 0;
}


int BeamerDecap::initialize(ErrorHandler *errh) {

    return 0;
}


void BeamerDecap::push_batch(int, PacketBatch* batch) {

    auto fnt = [this](Packet*&p) -> Packet* {
        WritablePacket* q =p->uniqueify();
        click_ip* encap_ip =  ((click_ip*)p->data());
        click_ip* real_ip = (click_ip*)(p->data() + sizeof(Beamer::IPHeaderWithPrevDIP));
        click_tcp* real_tcp = (click_tcp*)((unsigned char*)real_ip + (real_ip->ip_hl << 2));
        IPAddress dip = encap_ip->ip_dst;
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
EXPORT_ELEMENT(BeamerDecap)
ELEMENT_MT_SAFE(BeamerDecap)
