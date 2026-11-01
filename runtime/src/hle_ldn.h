// What nn::ldn (hle_ldn.cpp) and nn::socket on its network (hle_vsock.cpp) share.
#pragma once
#include <cstdint>

namespace nx {

bool ldn_enabled();          // NX_LDN=1
bool ldn_net_up();           // a network exists: this console made or joined it
uint32_t ldn_own_ip();       // 0 without a network (host byte order, as the two addresses here)
uint32_t ldn_broadcast_ip();

// A UDP datagram on the network, from a local socket.
void ldn_send(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port, const void* data, uint32_t len);
// A UDP datagram that reached this console: to the local sockets it is for.
void vsock_deliver(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port, const void* data,
                   uint32_t len);

// The link between consoles (ldn_link.cpp).
void link_host_start();
void link_stop();           // host or station: every connection ends (no lock of hle_ldn.cpp held)
void link_push_info();      // host: the NetworkInfo to every station
int link_scan(uint8_t* out, int max, const uint8_t* filter, int unused);  // NetworkInfos of hosts nearby: how many
// Joins the host of the scanned network with this BSSID: its node, and the NetworkInfo; -1 on failure.
int link_join(const uint8_t* bssid, const uint8_t* name, const uint8_t* mac, const uint8_t* version, uint8_t* info);

// What the link asks hle_ldn.cpp.
bool ldn_link_info(uint8_t* out);  // the hosted network's NetworkInfo
int ldn_link_add_node(const uint8_t* name, const uint8_t* mac, const uint8_t* version);  // host: its node, or -1
void ldn_link_remove_node(int node);
uint32_t ldn_node_ip(int node);
void ldn_link_set_info(const uint8_t* info);  // station: the host's new NetworkInfo
void ldn_link_lost();                         // station: the host is gone

}  // namespace nx
