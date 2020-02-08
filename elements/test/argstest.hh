// -*- c-basic-offset: 4 -*-
#ifndef CLICK_ARGSTEST_HH
#define CLICK_ARGSTEST_HH
#include <click/element.hh>
CLICK_DECLS

/*
=c

ArgsTest()

=s test

Test some arguments parsing.

=d

This element routes no packets and does all its work at initialization time.

*/

class ArgsTest : public Element { public:

    ArgsTest() CLICK_COLD;

    const char *class_name() const		{ return "ArgsTest"; }

    int initialize(ErrorHandler *) CLICK_COLD;

};

CLICK_ENDDECLS
#endif
