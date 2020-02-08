/*
 * IPHelper.hh - Provides several methods that can be used by elements to manage IP packets
 *
 * Romain Gaillard, Tom Barbette
 */

#ifndef MIDDLEBOX_IPHELPER_HH
#define MIDDLEBOX_IPHELPER_HH

#include <click/config.h>
#include <click/glue.hh>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>

CLICK_DECLS

/**
 * @class IPHelper
 * @brief This class provides several methods that can be used by elements that inherits
 * from it in order to manage IP packets.
 */
class IPHelper
{
public:
    /** @brief Return the length of the IP packet, obtained from the header
     * @param packet The IP packet
     * @return The length of the given IP packet, obtained from the IP header
     */
    static inline uint16_t packetTotalLength(Packet* packet);

    /** @brief Return the offset in the packet at which the IP header starts
     * @param packet The IP packet
     * @return The offset in the packet at which the IP header starts
     */
    static inline uint16_t getIPHeaderOffset(Packet* packet);

    /** @brief Set the length of the IP packet in the header
     * @param packet The IP packet
     * @param length The new length of the given IP packet
     */
    static inline void setPacketTotalLength(WritablePacket* packet, unsigned length);

    /** @brief Return the IP destination address of the packet
     * @param packet The IP packet
     * @return The IP destination address of the packet
     */
    static inline const uint32_t getDestinationAddress(Packet* packet);

    /** @brief Return the IP source address of the packet
     * @param packet The IP packet
     * @return The IP source address of the packet
     */
    static inline const uint32_t getSourceAddress(Packet* packet);

    /** @brief Recompute the IP checksum of the packet and set it in the IP header
     * @param packet The IP packet
     */
    static inline void computeIPChecksum(WritablePacket* packet);

    /**
     * Rewrite the src or dst IP address and src or dst port of the packet.
     */
    static inline void rewrite_ipport(WritablePacket* p, IPAddress ip, uint16_t port,
                           const int shift, bool is_tcp);


    static inline void rewrite_ips_ports(WritablePacket* q, IPPair pair,
					   uint16_t sport, uint16_t dport, bool is_tcp);
};

inline uint16_t IPHelper::packetTotalLength(Packet *packet)
{
    const click_ip *iph = packet->ip_header();

    return ntohs(iph->ip_len);
}

inline uint16_t IPHelper::getIPHeaderOffset(Packet *packet)
{
    return (((const unsigned char *)packet->ip_header()) - packet->data());
}

inline void IPHelper::setPacketTotalLength(WritablePacket* packet, unsigned length)
{
    click_ip *iph = packet->ip_header();
    iph->ip_len = htons(length);
}


inline void IPHelper::computeIPChecksum(WritablePacket *packet)
{
    click_ip *iph = packet->ip_header();

    //unsigned plen = ntohs(iph->ip_len) - (iph->ip_hl << 2);
    unsigned hlen = iph->ip_hl << 2;

    iph->ip_sum = 0;
    iph->ip_sum = click_in_cksum((const unsigned char *)iph, hlen);
}

inline const uint32_t IPHelper::getSourceAddress(Packet* packet)
{
    const click_ip *iph = packet->ip_header();

    return *(const uint32_t*)&iph->ip_src;
}

inline const uint32_t IPHelper::getDestinationAddress(Packet* packet)
{
    const click_ip *iph = packet->ip_header();

    return *(const uint32_t*)&iph->ip_dst;
}

inline void
IPHelper::rewrite_ipport(WritablePacket* p, IPAddress ip, uint16_t port,
                            const int shift, bool is_tcp) {
    assert(p->network_header());
    assert(p->transport_header());
    uint32_t old_hw, t_old_hw;
    uint32_t new_hw, t_new_hw;

    uint16_t *xip = reinterpret_cast<uint16_t *>(&p->ip_header()->ip_src);
    old_hw = (uint32_t) xip[(shift * 2) + 0] + xip[(shift*2) + 1];
    t_old_hw = old_hw;
    old_hw += (old_hw >> 16);

    memcpy(&xip[shift*2], &ip, 4);

    new_hw = (uint32_t) xip[(shift*2) + 0] + xip[(shift*2) + 1];
    t_new_hw = new_hw;
    new_hw += (new_hw >> 16);
    click_ip *iph = p->ip_header();
    click_update_in_cksum(&iph->ip_sum, old_hw, new_hw);

    uint16_t *xport = reinterpret_cast<uint16_t *>(&p->tcp_header()->th_sport);
    t_old_hw += (uint32_t) xport[shift + 0];
    t_old_hw += (t_old_hw >> 16);
    xport[shift + 0] = port;
    t_new_hw += (uint32_t) xport[shift + 0];
    t_new_hw += (t_new_hw >> 16);

    if (is_tcp)
        click_update_in_cksum(&p->tcp_header()->th_sum, t_old_hw, t_new_hw);
    else
        click_update_in_cksum(&p->udp_header()->uh_sum, t_old_hw, t_new_hw);
}

inline void
IPHelper::rewrite_ips_ports(WritablePacket* q, IPPair pair, uint16_t sport, uint16_t dport, bool is_tcp) {
    assert(q->network_header());
    assert(q->transport_header());
    uint32_t old_hw, t_old_hw;
    uint32_t new_hw, t_new_hw;

    uint16_t *xip = reinterpret_cast<uint16_t *>(&q->ip_header()->ip_src);
    old_hw = (uint32_t) xip[0] + xip[1] + xip[2] + xip[3];
    t_old_hw = old_hw;
    old_hw += (old_hw >> 16);

    memcpy(xip, &pair, 8);

    new_hw = (uint32_t) xip[0] + xip[1] + xip[2] + xip[3];
    t_new_hw = new_hw;
    new_hw += (new_hw >> 16);
    click_ip *iph = q->ip_header();
    click_update_in_cksum(&iph->ip_sum, old_hw, new_hw);

    uint16_t *xport = reinterpret_cast<uint16_t *>(&q->tcp_header()->th_sport);
    t_old_hw += (uint32_t) xport[0] + xport[1];
    t_old_hw += (t_old_hw >> 16);
    if (sport)
        xport[0] = sport;
    if (dport)
        xport[1] = dport;
    t_new_hw += (uint32_t) xport[0] + xport[1];
    t_new_hw += (t_new_hw >> 16);

    if (is_tcp)
        click_update_in_cksum(&q->tcp_header()->th_sum, t_old_hw, t_new_hw);
    else
        click_update_in_cksum(&q->udp_header()->uh_sum, t_old_hw, t_new_hw);
}


CLICK_ENDDECLS
#endif
