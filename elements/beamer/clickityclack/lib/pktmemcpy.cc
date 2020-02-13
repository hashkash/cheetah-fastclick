#include "pktmemcpy.hh"

CLICK_DECLS

namespace ClickityClack
{

#if 0
void moveMem(unsigned char *src, unsigned char *dst, ssize_t len)
{
	size_t leftoverLen = len % 16;
	size_t len64 = (len - leftoverLen) / 8;
	
	if (likely(len64))
		moveMem64(reinterpret_cast<uint64_t *>(src + leftoverLen), reinterpret_cast<uint64_t *>(dst + leftoverLen), len64);
	
	if (unlikely(!leftoverLen))
		return;
	
	do
	{
		len--;
		dst[len] = src[len];
	}
	while (likely(len >= 0));
}
#endif

/* for len >= 1 */
void memcpyFast64(uint64_t *dst, uint64_t *src, ssize_t len)
{
	int i = 0;
	
	do
	{
		dst[i] = src[i];
		i++;
	}
	while (likely(i < len));
}

/* for len >= 16 */
void memcpyFast(unsigned char *dst, unsigned char *src, ssize_t len)
{
	ssize_t leftoverLen = len % 8;
	ssize_t len64 = (len - leftoverLen) / 8;
	
	memcpyFast64(reinterpret_cast<uint64_t *>(dst + leftoverLen), reinterpret_cast<uint64_t *>(src + leftoverLen), len64);
	
	if (unlikely(!leftoverLen))
		return;
	
	int i = 0;
	
	do
	{
		dst[i] = src[i];
		i++;
	}
	while (likely(i < leftoverLen));
}

/* multiples of 8 only */
void moveMemBulk(uint64_t *src, uint64_t *dst, ssize_t len)
{
	if (len % 8)
		len = (len / 8 + 1) * 8;
	
	do
	{ 
		dst[len - 1] = src[len - 1];
		dst[len - 2] = src[len - 2];
		dst[len - 3] = src[len - 3];
		dst[len - 4] = src[len - 4];
		dst[len - 5] = src[len - 5];
		dst[len - 6] = src[len - 6];
		dst[len - 7] = src[len - 7];
		dst[len - 8] = src[len - 8];
		len -= 8;
	}
	while (likely(len > 0));
}

}

CLICK_ENDDECLS

ELEMENT_PROVIDES(ClickityClack_PktMemCpy)
