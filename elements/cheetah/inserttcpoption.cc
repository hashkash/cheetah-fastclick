// -*- c-basic-offset: 4; related-file-name: "../include/click/InsertTCPOption.hh"-*-
/*
 * InsertTCPOption.{cc,hh} -- element
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
#include "inserttcpoption.hh"

CLICK_DECLS

InsertTCPOption::InsertTCPOption() : _kind(TCPOPT_TIMESTAMP), _value("")
{
}

InsertTCPOption::~InsertTCPOption()
{
}

int
InsertTCPOption::configure(Vector<String> &conf, ErrorHandler *errh)
{

    if (Args(this, errh).bind(conf)
            .read_mp("KIND", _kind)
            .read_p("VALUE", _value)
            .consume() < 0)


    return 0;
}

int
InsertTCPOption::initialize(ErrorHandler *errh)
{

    return 0;
}


void
InsertTCPOption::push_batch(int port, PacketBatch *batch)
{
    auto fnt = [this](Packet* p_in) -> Packet* {
        WritablePacket* p = p_in->uniqueify();
        bool found = false;
        auto fnt = [this,&found](uint8_t opt, void* data) -> bool {
            if (opt == _kind) {
                memcpy(data,_value.data(),_value.length());
                return false;
                found = true;
            }
            return true;
        };
        iterateOptions(p,fnt);
        if (!found) {
            //Byte after all options
            uint8_t* endofopt = ((uint8_t*)p->tcp_header()) + (p->tcp_header()->th_off << 2);
            unsigned offset = endofopt - p->data();
            unsigned optlen = 0;
            if (_value.length() > 0)
                optlen = (2 + _value.length());
            else
                optlen = 1;

            int padlen = (((optlen - 1) / 4) + 1) * 4;
            click_chatter("OPT len %d, PAD len %d, TCP PTR %d, OFFSET %d", optlen,padlen, (uint8_t*)p->tcp_header() - p->data(), offset);


            p->ip_header()->ip_len = htons(padlen + ntohs(p->ip_header()->ip_len));
            p->tcp_header()->th_off += padlen / 4;

            p->pull(offset);
            p->put(padlen);
//            p = p->shift_data(padlen)->uniqueify();
            memmove((unsigned char *) p->data() + padlen, p->data(), p->length() - padlen);


            //endofopt -= 1;
            endofopt = p->data();
            *endofopt = _kind;
            endofopt += 1;
            *endofopt = _value.length() + 2;
            endofopt += 1;
            memcpy(endofopt,_value.data(),_value.length());
            endofopt += _value.length();
            padlen -= optlen;
            while (padlen > 0) {
                *endofopt = TCPOPT_NOP;
                endofopt+=1;
                padlen-=1;
            }
/*            if (endofopt < p->end_data())
                *endofopt = TCPOPT_EOL;*/
            p->push(offset);

            click_chatter("TCP PTR %d", (uint8_t*)p->tcp_header() - p->data());
        }
        return p;
    };
    EXECUTE_FOR_EACH_PACKET(fnt,batch);
    if (batch)
        output_push_batch(0,batch);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(InsertTCPOption)
//ELEMENT_MT_SAFE(InsertTCPOption) //Think carefully!
