#ifndef CLICK_BEAMERMUX_HH
#define CLICK_BEAMERMUX_HH

#include <click/config.h>
#include <click/element.hh>
#include <click/ipaddress.hh>
#include <click/batchelement.hh>
#include "../beamer/lib/dipmap.hh"
#include "../beamer/lib/ggencapper.hh"
#include "../beamer/clickityclack/lib/ipipencapper.hh"

CLICK_DECLS

class SimpleBeamerLB: public BatchElement
{
public:
	SimpleBeamerLB();
	
	~SimpleBeamerLB();
	
	const char *class_name() const { return "SimpleBeamerLB"; }
	
	const char *port_count() const { return "1-/="; }
	
	const char *processing() const { return AGNOSTIC; }
	
	int configure(Vector<String> &conf, ErrorHandler *errh);
	
	int initialize(ErrorHandler *errh);
	
	Packet *simple_action(Packet *p);
	
#if HAVE_BATCH
	PacketBatch *simple_action_batch(PacketBatch *head);
#endif
	
	static int writeHandler(const String &conf, Element *e, void *thunk, ErrorHandler *errh);
	
	static String readHandler(Element *e, void *thunk);
	
	void add_handlers();
private:

    void rebalance();
    void remove_server();	
    void add_server();
	Beamer::GGEncapper ggEncapper;
	
	IPAddress _vip;
    Vector <IPAddress> _dsts;

	Vector<Beamer::DIPHistoryEntry> bucketMap;
    Vector<unsigned> _spares;
    Vector<unsigned> _actives;
	
	Packet *handleTCP(Packet *p);
 };

CLICK_ENDDECLS

#endif /* CLICK_BEAMERMUX_HH */
