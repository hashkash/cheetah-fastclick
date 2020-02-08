#ifndef CLICK_FLOWCHEETAHPROXY_HH
#define CLICK_FLOWCHEETAHPROXY_HH
#include <click/config.h>
#include <click/tcphelper.hh>
#include <click/multithread.hh>
#include <click/glue.hh>
#include <click/vector.hh>
#include <clicknet/mpls.h>

#include <click/flow/flowelement.hh>


CLICK_DECLS

struct CheetahProxyEntry {
    uint32_t cookie;
};

class FlowCheetahProxyReverse;

/**
=c

FlowCheetahProxy([I<KEYWORDS>])

=s flow



=d

Proxy for Cheetah cookie

Keyword arguments are:

=over 8

=item DST

=back

=e
	FlowCheetahProxy()

=a

FlowCheetahProxy, FlowIPNAT */

class FlowCheetahProxy : public FlowStateElement<FlowCheetahProxy,CheetahProxyEntry>, public TCPHelper {

public:

    FlowCheetahProxy() CLICK_COLD;
    ~FlowCheetahProxy() CLICK_COLD;

    const char *class_name() const		{ return "FlowCheetahProxy"; }
    const char *port_count() const		{ return "1/1"; }
    const char *processing() const		{ return PUSH; }


    int configure(Vector<String> &, ErrorHandler *) override CLICK_COLD;
    int initialize(ErrorHandler *errh) override CLICK_COLD;

    static const int timeout = -1;
    bool new_flow(CheetahProxyEntry*, Packet*);
    void release_flow(CheetahProxyEntry*) {};

    void push_batch(int, CheetahProxyEntry*, PacketBatch *);


private:

    IPAddress _vip;
    bool _own_state;
    bool _accept_nonsyn;

    friend class FlowCheetahProxyReverse;

};


/**
=c

FlowCheetahProxyReverse(LB)

=s flow

Reverse side for FlowCheetahProxyReverse.

=d



Keyword arguments are:

=over 8

=item DST

IP Address. Can be repeated multiple times, once per destination.

=item VIP
IP Address of this load-balancer.

=back

=e
	FlowCheetahProxy(VIP 10.220.0.1, DST 10.221.0.1, DST 10.221.0.2, DST 10.221.0.3)

=a

FlowCheetahProxy, FlowIPNAT */

class FlowCheetahProxyReverse : public BatchElement {

public:

    FlowCheetahProxyReverse() CLICK_COLD;
    ~FlowCheetahProxyReverse() CLICK_COLD;

    const char *class_name() const      { return "FlowCheetahProxyReverse"; }
    const char *port_count() const      { return "1/1"; }
    const char *processing() const      { return PUSH; }


    int configure(Vector<String> &, ErrorHandler *) override CLICK_COLD;
    int initialize(ErrorHandler *errh) override CLICK_COLD;

    void push_batch(int, PacketBatch *) override;
private:
    FlowCheetahProxy* _lb;
};


CLICK_ENDDECLS
#endif
