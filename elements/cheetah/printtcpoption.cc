// -*- c-basic-offset: 4; related-file-name: "../include/click/PrintTCPOption.hh"-*-
/*
 * PrintTCPOption.{cc,hh} -- element
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
#include "printtcpoption.hh"

CLICK_DECLS

PrintTCPOption::PrintTCPOption() : _kind(TCPOPT_TIMESTAMP)
{
}

PrintTCPOption::~PrintTCPOption()
{
}

int
PrintTCPOption::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (Args(this, errh).bind(conf)
            .read_mp("KIND", _kind)
            .consume() < 0)


    return 0;
}

int
PrintTCPOption::initialize(ErrorHandler *errh)
{

    return 0;
}


void
PrintTCPOption::push_batch(int port, PacketBatch *batch)
{
    auto fnt = [this](Packet* p_in) -> Packet* {
        //WritablePacket* p = p_in->uniqueify();

        auto fnt = [this](uint8_t opt, void* data) -> bool {
            if (opt == _kind) {
                if (_kind == TCPOPT_TIMESTAMP)
                    click_chatter("KIND %d (TS) : ecr %u val %u", _kind, ((tcp_opt_timestamp*)data)->ts_ecr,  ((tcp_opt_timestamp*)data)->ts_val );
                else if (_kind == TCPOPT_ECHO)
                    click_chatter("KIND %d (ECHO) : echo %u", _kind, ((tcp_opt_echo*)data)->echo);
                else if (_kind == TCPOPT_ECHO_REPLY)
                    click_chatter("KIND %d (ECHOREPLY) : echo %u", _kind, ((tcp_opt_echo*)data)->echo);
                else
                    click_chatter("KIND %d", _kind);
                return false;
            }
            return true;
        };
        iterateOptions(p_in,fnt);
        return p_in;
    };
    EXECUTE_FOR_EACH_PACKET(fnt,batch);
    if (batch)
        output_push_batch(0,batch);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(PrintTCPOption)
//ELEMENT_MT_SAFE(PrintTCPOption) //Think carefully!
