/**
 * Most code is taken from Beamer-LB, see https://github.com/Beamer-LB
 *
 * It is simplified to use only local data (no synchronized dataplane), no MPTCP, and only TCP. To be more fair with our system.
 */
#include "simplebeamerlb.hh"
#include <click/args.hh>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <click/error.hh>
#include "../beamer/clickityclack/lib/checksumfixup.hh"
#include "../beamer/lib/p4crc32.hh"

#include <queue>
#include <vector>
#include <algorithm>

CLICK_DECLS

using namespace Beamer;
using namespace ClickityClack;

static inline uint32_t beamerHash(const click_ip *ipHeader, const click_tcp *tcpHeader)
{
	struct HashTouple touple = { ipHeader->ip_src.s_addr, tcpHeader->th_sport };
	return p4_crc32_6((char *)&touple);
}

static inline uint32_t beamerHash(const click_ip *ipHeader, const click_udp *udpHeader)
{
	struct HashTouple touple = { ipHeader->ip_src.s_addr, udpHeader->uh_sport };
	return p4_crc32_6((char *)&touple);
}

SimpleBeamerLB::SimpleBeamerLB()
{
}

SimpleBeamerLB::~SimpleBeamerLB() {}

int SimpleBeamerLB::configure(Vector<String> &conf, ErrorHandler *errh)
{
	int ringSize = 100*32;
    int nserver = 0;
	
	if (Args(conf, this, errh)
		.read("RING_SIZE", BoundedIntArg(0, (int)0x800000), ringSize)
        .read_mp("VIP", _vip)
        .read_all("DST", _dsts)
        .read("NSERVER", nserver)
        .complete() < 0)
	{
		return -1;
	}

	bucketMap.resize(ringSize);
    if (nserver == 0) 
        nserver = _dsts.size();

    for (int i = 0; i < nserver; i++) 
        _actives.push_back(i);

    for (int i = nserver; i < _dsts.size(); i++) 
        _spares.push_back(i);
	
	return 0;
}


struct ServerWeight {
    int dst_id;
    int weight;
};
auto comp = [](const ServerWeight &a, const ServerWeight &b) -> bool {
    return a.weight > b.weight;
};


using namespace std;
typedef priority_queue <ServerWeight, vector<ServerWeight>, std::reference_wrapper<decltype(comp)>> pq;

pq w_servers(std::ref(comp)); 

int SimpleBeamerLB::initialize(ErrorHandler *errh)
{
	(void)errh;


	int fac = bucketMap.size() / _actives.size();
    for (int i = 0; i < _actives.size(); i++) {
        w_servers.push((ServerWeight){(int)_actives[i], fac});
    }
    click_jiffies_t now = click_jiffies();
    for (int i = 0; i < bucketMap.size(); i++) {
        unsigned idx = i / fac;
        if (idx >= _actives.size()) {
            ServerWeight s = w_servers.top();
            w_servers.pop();
            s.weight++;
            bucketMap[i].current = _dsts[s.dst_id];
            w_servers.push(s);
        } else {
            bucketMap[i].current = _dsts[_actives[idx]];
        }
        bucketMap[i].prev = 0;
        bucketMap[i].timestamp = now;
        //click_chatter("Bucket is to %d", bucketMap[i].current);
    }
	return 0;
}


void SimpleBeamerLB::rebalance() {
	    Vector<Beamer::DIPHistoryEntry> newBucketMap;
//        int avg = bucketMap.size() / _actives.size();
//        newBucketMap.resize(bucketMap.size());
        Vector<ServerWeight> sarray;
        while (!w_servers.empty()) {
            sarray.push_back(w_servers.top());
            w_servers.pop();
        }
        click_jiffies_t now = click_jiffies();

        std::sort (sarray.begin(), sarray.end(), comp);
        while (true) {
            ServerWeight &s = sarray.back();
            ServerWeight &o = sarray.front();
//            click_chatter("Rebalancing %d and %d -> %d < %d", s.dst_id, o.dst_id, s.weight, o.weight);
            if (s.weight >= o.weight -1)
                break;

            //TODO : find a bucket of o
            int b;

            unsigned ts =-1;
            uint32_t sdst = _dsts[o.dst_id];
            for (int i=0;i < bucketMap.size();i++) {
                if (bucketMap[i].current == sdst && bucketMap[i].timestamp < ts) {
                    b = i;
                }
            }
            assert(b >= 0);          
            //TODO : assign it to s
            bucketMap[b].timestamp=now;
            bucketMap[b].prev = bucketMap[b].current;
            bucketMap[b].current = _dsts[s.dst_id];

            s.weight++;
            o.weight--;
            //Optimize that, one day
            std::sort (sarray.begin(), sarray.end(), comp);
        }
//      click_chatter("Finished");
        for (int i = 0; i < sarray.size(); i++) {
            w_servers.push(sarray[i]);
        }
}

void SimpleBeamerLB::add_server() {
        if (_spares.size() == 0) {
            click_chatter("No server to add!");
            return;
        }
        int spare = _spares.front();
        _spares.pop_front();
        _actives.push_back(spare);
        w_servers.push(ServerWeight{.dst_id = spare, .weight = 0});
        rebalance();

}

void SimpleBeamerLB::remove_server() {
        if (_actives.size() <= 1) {
            click_chatter("Cannot remove all servers!");
            return;
        }
        int spare = _actives.front();
        _actives.pop_front();
        _spares.push_back(spare);


        pq new_servers(std::ref(comp)); 
        while (!w_servers.empty()) {
            ServerWeight w = w_servers.top();
            w_servers.pop();
            if (w.dst_id == spare)
                continue;
            new_servers.push(w);
        }
        w_servers.swap(new_servers);
        click_jiffies_t now = click_jiffies();
        for (int i = 0; i < bucketMap.size(); i++) {
            if (bucketMap[i].current == (uint32_t)_dsts[spare]) {
                ServerWeight s = w_servers.top();
                w_servers.pop();
                s.weight++;
                bucketMap[i].prev = _dsts[spare];
                bucketMap[i].current = _dsts[s.dst_id];
                w_servers.push(s);
                bucketMap[i].timestamp = now;
            }
        }
}

Packet *SimpleBeamerLB::handleTCP(Packet *p)
{
	const click_ip *ipHeader = p->ip_header();
	const click_tcp *tcpHeader = p->tcp_header();
	uint32_t dip;
	uint32_t prevDip = 0;
	uint32_t ts;
	uint32_t gen = 0;
	
    uint32_t hash = beamerHash(ipHeader, tcpHeader);
    DIPHistoryEntry &entry = bucketMap.unchecked_at(hash % bucketMap.size());
    dip = entry.current;
    prevDip = entry.prev;
    ts = entry.timestamp;
    //click_chatter("%x %x",dip,prevDip);

    p = ggEncapper.encapsulate(p, _vip.addr(), dip, prevDip, ts, gen);
    p->set_dst_ip_anno(dip);
    return p;
}

#if HAVE_BATCH
PacketBatch *SimpleBeamerLB::simple_action_batch(PacketBatch *head)
{
	Packet *current = head;
	Packet *last = head;
	
	while (current != NULL)
	{
		Packet *result = NULL;
		
    	result = handleTCP(current);
	
		if (current == head)
		{
			head = PacketBatch::start_head(result);
			head->set_next(current->next());
		}
		else
		{
			last->set_next(result);
			result->set_next(current->next());
		}
		
		last = result;
		current = result->next();
	}
	return head;
}
#endif

Packet *SimpleBeamerLB::simple_action(Packet *p)
{
    
    handleTCP(p);
    return p;
}

enum {h_nb_active_servers, h_nb_total_servers, h_add_server, h_remove_server};

int SimpleBeamerLB::writeHandler(const String &conf, Element *e, void *thunk, ErrorHandler *errh)
{
	SimpleBeamerLB *me = (SimpleBeamerLB *)e;
	
	int err;
	
	switch ((intptr_t)thunk)
	{
        case h_add_server:
            me->add_server();
            break;
        case h_remove_server:
            me->remove_server();
            break;
	default:
		return errh->error("bad operation");
	}
	
	return 0;
}

String SimpleBeamerLB::readHandler(Element *e, void *thunk)
{
	SimpleBeamerLB *me = (SimpleBeamerLB *)e;
	
	switch ((intptr_t)thunk) {	
        case h_nb_total_servers:
            return String(me->_actives.size()+me->_spares.size());
        case h_nb_active_servers:
            return String(me->_actives.size());
	default:
		return "<error: bad operation>";
	}
	
	return "";
}

void SimpleBeamerLB::add_handlers()
{
/*	add_write_handler("assign", &writeHandler, H_ASSIGN);
	add_write_handler("dump",   &writeHandler, H_DUMP);
	
	add_read_handler("gen", &readHandler, H_GEN);*/
    add_read_handler("nb_active_servers", readHandler, h_nb_active_servers);
    add_read_handler("nb_total_servers", readHandler, h_nb_total_servers);
    add_write_handler("add_server", writeHandler, h_add_server);
    add_write_handler("remove_server", writeHandler, h_remove_server);

}


#include "../beamer/lib/p4crc32.cc"
#include "../beamer/lib/ggencapper.cc"
#include "../beamer/clickityclack/lib/pktmemcpy.cc"

CLICK_ENDDECLS

EXPORT_ELEMENT(SimpleBeamerLB)

