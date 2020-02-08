// -*- c-basic-offset: 4; related-file-name: "../include/click/HasTCPOption.hh"-*-
/*
 * HasTCPOption.{cc,hh} -- element
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
#include "hastcpoption.hh"

CLICK_DECLS

HasTCPOption::HasTCPOption()
{
}

HasTCPOption::~HasTCPOption()
{
}

int
HasTCPOption::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (Args(this, errh).bind(conf)
            .consume() < 0)


    return 0;
}

int
HasTCPOption::initialize(ErrorHandler *errh)
{

    return 0;
}


void
HasTCPOption::push_batch(int port, PacketBatch *batch)
{
    auto fnt = [this](Packet* p_in) -> int {
        WritablePacket* p = p_in->uniqueify();

        tcp_opt_timestamp* ts = parse_ts_from_client(p);
        return ts == 0 ? 1: 0;
    };
    CLASSIFY_EACH_PACKET(2,fnt,batch,output_push_batch);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(HasTCPOption)
//ELEMENT_MT_SAFE(HasTCPOption) //Think carefully!
