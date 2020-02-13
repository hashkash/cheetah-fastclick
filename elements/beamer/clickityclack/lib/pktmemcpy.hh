#ifndef CLICK_CLICKITYCLACK_PKTMEMCPY_HH
#define CLICK_CLICKITYCLACK_PKTMEMCPY_HH

#include <click/config.h>
#include <click/glue.hh>

CLICK_DECLS

namespace ClickityClack
{

/* for len >= 1 */
void memcpyFast64(uint64_t *dst, uint64_t *src, ssize_t len);

/* for len >= 16 */
void memcpyFast(unsigned char *dst, unsigned char *src, ssize_t len);

/* multiples of 8 only */
void moveMemBulk(uint64_t *src, uint64_t *dst, ssize_t len);

}

CLICK_ENDDECLS

#endif /* CLICK_CLICKITYCLACK_PKTMEMCPY_HH */
