#ifndef CLICK_BEAMERVERIFIER_HH
#define CLICK_BEAMERVERIFIER_HH
#include <click/config.h>
#include <click/tcphelper.hh>
#include <click/multithread.hh>
#include <click/glue.hh>
#include <click/vector.hh>

#include <click/flow/flowelement.hh>


CLICK_DECLS

struct BeamerVerifierEntry {   
    IPAddress dip;
};


class SimpleBeamerLB;
/**
=c

BeamerVerifier([I<KEYWORDS>])

=s flow



=d

Proxy for Cheetah cookie

Keyword arguments are:

=over 8

=item DST

=back

=e
	BeamerVerifier()

=a

BeamerVerifier, FlowIPNAT */


class BeamerVerifier : public FlowStateElement<BeamerVerifier,BeamerVerifierEntry>, public TCPHelper {

public:

    BeamerVerifier() CLICK_COLD;
    ~BeamerVerifier() CLICK_COLD;

    const char *class_name() const		{ return "BeamerVerifier"; }
    const char *port_count() const		{ return "1/1"; }
    const char *processing() const		{ return PUSH; }


    int configure(Vector<String> &, ErrorHandler *) override CLICK_COLD;
    int initialize(ErrorHandler *errh) override CLICK_COLD;

    static const int timeout = -1;
    bool new_flow(BeamerVerifierEntry*, Packet*);
    void release_flow(BeamerVerifierEntry*) {};

    void push_batch(int, BeamerVerifierEntry*, PacketBatch *);


private:

    SimpleBeamerLB* _beamer;
    bool _dosave;
};



CLICK_ENDDECLS
#endif
