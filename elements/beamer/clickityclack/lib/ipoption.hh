#ifndef CLICK_CLICKITYCLACK_IPOPTION_HH
#define CLICK_CLICKITYCLACK_IPOPTION_HH

#include <click/config.h>
#include <click/glue.hh>

CLICK_DECLS

namespace ClickityClack
{

struct IPOption
{
#if CLICK_BYTE_ORDER == CLICK_BIG_ENDIAN
	uint8_t copied : 1,
		oclass: 2,
		num : 5;
#elif CLICK_BYTE_ORDER == CLICK_LITTLE_ENDIAN
	uint8_t num : 5,
		oclass: 2,
		copied : 1;
#else
#error "unknown byte order"
#endif
	uint8_t len;
} __attribute__((packed));

}

CLICK_ENDDECLS

#endif // CLICK_CLICKITYCLACK_IPOPTION_HH
