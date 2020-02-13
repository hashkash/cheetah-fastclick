#ifndef CLICK_BEAMERDECAP_HH
#define CLICK_BEAMERDECAP_HH
#include <click/config.h>
#include <click/tcphelper.hh>
#include <click/multithread.hh>
#include <click/glue.hh>
#include <click/vector.hh>

#include <click/batchelement.hh>


CLICK_DECLS


class SimpleBeamerLB;
/**
=c

BeamerDecap([I<KEYWORDS>])

=s flow



=d

Proxy for Cheetah cookie

Keyword arguments are:

=over 8

=item DST

=back

=e
	BeamerDecap()

=a

BeamerDecap, FlowIPNAT */


class BeamerDecap : public BatchElement, public TCPHelper {

public:

    BeamerDecap() CLICK_COLD;
    ~BeamerDecap() CLICK_COLD;

    const char *class_name() const		{ return "BeamerDecap"; }
    const char *port_count() const		{ return "1/1"; }
    const char *processing() const		{ return PUSH; }


    int configure(Vector<String> &, ErrorHandler *) override CLICK_COLD;
    int initialize(ErrorHandler *errh) override CLICK_COLD;

    void push_batch(int, PacketBatch *);


};



CLICK_ENDDECLS
#endif
