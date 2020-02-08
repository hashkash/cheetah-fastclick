#ifndef CLICK_Cheetah_HH
#define CLICK_Cheetah_HH

#include <click/tcphelper.hh>
#include <click/ipflowid.hh>

class Cheetah : public TCPHelper {
public:
	Cheetah() : _verbose(0) {

	}
protected:

	//shift : 0 for val, 1 for ecr
	inline void
	rewrite_ts(WritablePacket* p, tcp_opt_timestamp* ts, const int shift, uint32_t new_ts) {
		if (shift == 0)
			ts->ts_val = new_ts;
		else
			ts->ts_ecr = new_ts;
	}


	inline int find_rand_offset(int b, int hash) {
	    return b ^ hash;
	    //TODO : Multiply by a certain number of _buckets.size()
	}

	inline int hash(const Packet* p, const bool reverse = false);

	inline tcp_opt_timestamp* parse_ts_from_client(Packet* p);
	inline tcp_opt_timestamp* parse_ts_from_server(Packet* p);
	int _verbose;

};
#define COOKIE_MSB 1
#ifdef COOKIE_MSB
#define TS_BITS 15
#define TS_SHIFT 16
#define TS_VERSION_BIT 15
#define TS_LSB_MASK ((1 << TS_SHIFT) - 1)

#define TS_SHIFTED_VALVER_MASK ((1 << TS_SHIFT) - 1)
#define TS_SHIFTED_VAL_MASK ((1 << TS_VERSION_BIT) - 1)
#define TS_SHIFTED_VER_MASK (1 << (TS_VERSION_BIT))

#define TS_GET_COOKIE(b) ((b >> TS_SHIFT) & TS_SHIFTED_VAL_MASK)
#define TS_GET_VERSION(b) (b >> (TS_SHIFT + TS_VERSION_BIT))

#define TS_GET_LSB(b) (b & TS_LSB_MASK)
#else

#define TS_BITS 16
#define TS_SHIFT 0
#define TS_VAL_SHIFT 16
#define TS_VERSION_BIT 31
#define TS_COOKIE_MASK ((1 << TS_VAL_SHIFT) - 1)
#define TS_GET_VAL(b) (b >> TS_VAL_SHIFT)
#define TS_GET_COOKIE(b) (b & TS_COOKIE_MASK)
#define TS_GET_VERSION(b) (b >> TS_VERSION_BIT)

#define TS_GET_LSB(b) (b & TS_COOKIE_MASK)
#define TS_GET_MSB(b) (b >> TS_VAL_SHIFT)
#endif

inline tcp_opt_timestamp* Cheetah::parse_ts_from_client(Packet* p) {
    tcp_opt_timestamp* ts = 0;
    if (isSyn(p)) {
        // MSS SackOK(or any 2 bytes) TS
        uint8_t* ptr =(uint8_t*) (p->tcp_header() + 1);
        //0x0a080204b4050402 in host byte order
        uint64_t real64 = *(uint64_t*)ptr;
        uint64_t opt64 = real64 & 0xffffff000000ffff;
        //click_chatter("val 0x%" PRIx64 " -> 0x%" PRIx64 ,real64,  opt64);
        if (likely(opt64 == 0xa08020000000402)) {
            ts = (tcp_opt_timestamp*)((unsigned char*)ptr + 8);
            goto found;
        }
        //TODO : good in theory but need to check byte order
        // MSS NOP WSCALE NOP NOP TS
        /*0000   02 04 05 78 01 03 03 06 01 01 08 0a 0b 9b a6 92  ...x............
          0010   00 00 00 00 04 02 00 00   */
/*
        __m256i val  = _mm256_set_epi64x ((uint64_t)0x02040000,(uint64_t)0x01030000, (uint64_t)0x0101080a,00000000);
        //__m256i mask = _mm256_set_epi64x ((uint64_t)0xffff0000,(uint64_t)0xffff0000, (uint64_t)0xffffffff,00000000);
        __m256i optStart = _mm256_lddqu_si256(reinterpret_cast<const __m256i*>(ptr));
        __mmask8 ret =  _mm256_mask_cmpeq_epi32_mask(0b10101100,optStart,val);
        //click_chatter("Val %d val", ret);
        if (likely(ret == 0b10101100)) {
            ts = (tcp_opt_timestamp*)((unsigned char*)ptr + 24);
            goto found;
        }*/
        if (unlikely(_verbose > 0))
            click_chatter("Parsing of SYN missed");

    } else {
		// NOP NOP Timestamp
		// NOP NOP Timestamp [NOP NOP SAck]
		// 01 01 08 0a 6b 8f 7a a2 71 7d d6 61
		unsigned val = 0x0a080101;//ntohs 0x0101080a;
		uint8_t *optStart = const_cast<uint8_t *>((uint8_t *) (p->tcp_header() + 1));
		if (likely((*(uint32_t*)optStart) == val)) {
			ts = (tcp_opt_timestamp*)(optStart + 4);
			goto found;
		}
        if (unlikely(_verbose > 0))
            click_chatter("Parsing of CLIENT established missed");
    }


    {
        auto fnt = [&ts](uint8_t opt, void* data) -> bool {
            if (opt == TCPOPT_TIMESTAMP) {
                ts = (tcp_opt_timestamp*)data;
                return false;
            }
            return true;
        };
        iterateOptions(p,fnt);
    }
    found:
    return ts;
}

inline tcp_opt_timestamp* Cheetah::parse_ts_from_server(Packet* p)
{
	tcp_opt_timestamp* ts = 0;
	        if (isSyn(p)) {
	            //MSS SackOK(or any 2bytes opt) TS [whatever]
	            uint8_t* ptr =(uint8_t*) (p->tcp_header() + 1);
	            uint64_t real64 = *(uint64_t*)ptr;
	            uint64_t opt64 = real64 & 0xffffff000000ffff;
	            if (likely(opt64 == 0xa08020000000402)) {
	                ts = (tcp_opt_timestamp*)((unsigned char*)ptr + 8);
	                goto found;
	            }

	            if (unlikely(_verbose > 0))
	                click_chatter("Parsing of SERVER syn missed");

	        } else {
	            // NOP NOP Timestamp
	            // NOP NOP Timestamp [NOP NOP SAck]
	            // 01 01 08 0a 6b 8f 7a a2 71 7d d6 61
	            //int val = 0x0101080a;
	            unsigned val = 0x0a080101;//ntohs 0x0101080a;
	            uint8_t *optStart = const_cast<uint8_t *>((uint8_t *) (p->tcp_header() + 1));
	            if (likely((*(uint32_t*)optStart) = val)) {
	                ts = (tcp_opt_timestamp*)(optStart + 4);
	                goto found;
	            }

	            if (unlikely(_verbose > 0))
	                click_chatter("Parsing of SERVER established missed");
	        }

	        {
	        auto fnt = [&ts](uint8_t opt, void* data) -> bool {
	            if (opt == TCPOPT_TIMESTAMP) {
	                ts = (tcp_opt_timestamp*)data;
	                return false;
	            }
	            return true;
	        };
	        iterateOptions(p,fnt);
	        }

	        found:
			return ts;
}
inline int Cheetah::hash(const Packet* p, const bool reverse) {
#if CHEETAH_HW_HASH
    return AGGREGATE_ANNO(p) & ((1 << 15) - 1) ;
#else
    //We hash without the server ip, so hash is symmetric (reverse tells us the side)
    const click_ip *iph = p->ip_header();
    const click_udp *udph = p->udp_header();

    if (!p->has_network_header()   ||
        !p->has_transport_header() ||
        !IP_FIRSTFRAG(iph)) {
        return 0;
    }

    if (!reverse) { //Forward packet
        return IPFlowID( iph->ip_src.s_addr, udph->uh_sport,
	       0, udph->uh_dport ).hashcode() & ((1 << 15) - 1);
    } else {
        return IPFlowID( iph->ip_dst.s_addr, udph->uh_dport,
	        0, udph->uh_sport ).hashcode() & ((1 << 15) - 1);
    }
#endif
}


#endif
