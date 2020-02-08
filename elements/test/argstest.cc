// -*- c-basic-offset: 4 -*-
/*
 * argstest.{cc,hh} -- regression test element for Ars
 * Tom Barbette
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
#include "argstest.hh"
#include <click/args.hh>
#include <click/error.hh>

CLICK_DECLS

ArgsTest::ArgsTest()
{
}

#define CHECK(x, a, b) if (!(x)) return errh->error("%s:%d: test `%s' failed [%llu, %u]", __FILE__, __LINE__, #x, a, b);
#define CHECK0(x) if (!(x)) return errh->error("%s:%d: test `%s' failed", __FILE__, __LINE__, #x);

    
int
ArgsTest::initialize(ErrorHandler *errh)
{

    HashTable<String,uint64_t> map;
    map.set("ONE",1);
    map.set("TWO",2);
    uint64_t v;
    CHECK0(MaskArg(&map).parse("ONE | TWO",v));
    CHECK0(v == 3);
    CHECK0(MaskArg(&map).parse("ONE|TWO",v));
    CHECK0(v == 3);
    CHECK0(MaskArg(&map).parse("   ONE   |    TWO    ",v));
    CHECK0(v == 3);

    errh->message("All tests pass!");
    return 0;
}

EXPORT_ELEMENT(ArgsTest)
ELEMENT_REQUIRES(userlevel int64)
CLICK_ENDDECLS
