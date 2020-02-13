#ifndef CLICK_CLICKITYCLACK_ENCAPPER_HH
#define CLICK_CLICKITYCLACK_ENCAPPER_HH

#include <click/config.h>
#include <clicknet/ip.h>
#include <click/packet.hh>
#include <click/glue.hh>

CLICK_DECLS

namespace ClickityClack
{

class IPIPEncapper
{
	click_ip iph;
	
public:
	IPIPEncapper(uint8_t ttl = 250);
	
	WritablePacket *encapsulate(Packet *p, uint32_t src, uint32_t dst);
};

}

CLICK_ENDDECLS

#endif /* CLICK_CLICKITYCLACK_ENCAPPER_HH */
