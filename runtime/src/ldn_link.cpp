// The link between consoles for local play (NX_LDN=1, docs/LOCAL_PLAY.md): what the wireless network is on a Switch.
// A host answers searches on UDP (NX_LDN_PORT, default 39500) with its NetworkInfo and listens on TCP on the same
// port. A station keeps one TCP connection to the host, which gives it a node, sends the NetworkInfo at every change
// and relays the game's datagrams between the players. A search asks this computer, the LAN's broadcast and every
// address of NX_LDN_JOIN (host[:port], comma separated; a virtual LAN that forwards no broadcasts needs it).
// The design follows MHGURecomp (morerokk, MIT): runtime/net/ldn.c and vsock.c, docs/STATUS.md "Local Play over IP".
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
using sock_t = SOCKET;
constexpr sock_t kBadSock = INVALID_SOCKET;
static void sock_close(sock_t s) { closesocket(s); }
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
using sock_t = int;
constexpr sock_t kBadSock = -1;
static void sock_close(sock_t s) { close(s); }
#endif

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <nx/runtime.h>

#include "hle_ldn.h"

namespace nx {

namespace {

constexpr uint16_t kDefaultPort = 39500;
constexpr char kProbe[] = "ACNHLDN1?", kAnswer[] = "ACNHLDN1!";
constexpr size_t kMagicSize = 9, kInfoSize = 0x480;
constexpr int kMaxNodes = 8;
constexpr uint32_t kMaxFrame = 0x10100;
constexpr int kScanMs = 300;

enum Frame : uint8_t { kJoin = 1, kWelcome = 2, kInfo = 3, kPacket = 4, kRefused = 5 };
enum Role { kNoRole, kHost, kStation };

struct PacketHeader {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
};

struct Peer {
    sock_t fd = kBadSock;
    std::mutex tx;
    std::thread reader;
    std::atomic<bool> alive{false};
    uint32_t ip = 0;
};

struct Found {
    uint8_t bssid[6];
    sockaddr_in addr;
};

std::atomic<Role> g_role{kNoRole};
std::atomic<bool> g_stopping{false};
sock_t g_udp = kBadSock, g_listen = kBadSock;
std::thread g_udp_thread, g_accept_thread;
std::mutex g_peers_lock;
Peer g_peers[kMaxNodes];  // host: [node]; [0] unused. station: [0] is the link to the host.
std::mutex g_found_lock;
std::vector<Found> g_found;

uint16_t link_port() {
    const char* e = std::getenv("NX_LDN_PORT");
    const int p = e ? std::atoi(e) : 0;
    return p > 0 && p < 65536 ? uint16_t(p) : kDefaultPort;
}

void net_init() {
#ifdef _WIN32
    static const bool done = [] {
        WSADATA d;
        return WSAStartup(MAKEWORD(2, 2), &d) == 0;
    }();
    (void)done;
#endif
}

void stop_socket(sock_t& s) {
    if (s == kBadSock) return;
#ifdef _WIN32
    shutdown(s, SD_BOTH);
#else
    shutdown(s, SHUT_RDWR);
#endif
    sock_close(s);
    s = kBadSock;
}

bool send_all(sock_t s, const void* p, size_t n) {
    const char* b = static_cast<const char*>(p);
    while (n) {
        const int r = int(send(s, b, int(n), 0));
        if (r <= 0) return false;
        b += r, n -= size_t(r);
    }
    return true;
}

bool read_all(sock_t s, void* p, size_t n) {
    char* b = static_cast<char*>(p);
    while (n) {
        const int r = int(recv(s, b, int(n), 0));
        if (r <= 0) return false;
        b += r, n -= size_t(r);
    }
    return true;
}

// A frame: its type, the size of what follows (u32), then the two parts of it.
bool send_frame(Peer& peer, uint8_t type, const void* a, uint32_t alen, const void* b = nullptr, uint32_t blen = 0) {
    std::vector<uint8_t> f(5 + alen + blen);
    const uint32_t size = alen + blen;
    f[0] = type;
    std::memcpy(&f[1], &size, 4);
    if (alen) std::memcpy(&f[5], a, alen);
    if (blen) std::memcpy(&f[5 + alen], b, blen);
    std::lock_guard lk(peer.tx);
    return peer.fd != kBadSock && send_all(peer.fd, f.data(), f.size());
}

bool read_frame(sock_t s, uint8_t& type, std::vector<uint8_t>& out) {
    uint8_t h[5];
    if (!read_all(s, h, 5)) return false;
    uint32_t size;
    std::memcpy(&size, h + 1, 4);
    if (size > kMaxFrame) return false;
    type = h[0];
    out.resize(size);
    return !size || read_all(s, out.data(), size);
}

void no_delay(sock_t s) {
    int one = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof one);
}

// Host: to the host's own sockets and/or the stations. from: the sending node, 0 = the host.
void route(int from, const PacketHeader& h, const void* data, uint32_t len) {
    const bool all = h.dst_ip == ldn_broadcast_ip() || h.dst_ip == 0xFFFFFFFFu;
    if (all || h.dst_ip == ldn_own_ip()) vsock_deliver(h.src_ip, h.src_port, h.dst_ip, h.dst_port, data, len);
    for (int i = 1; i < kMaxNodes; i++) {
        Peer& p = g_peers[i];
        if (i == from || !p.alive || !(all || p.ip == h.dst_ip)) continue;
        send_frame(p, kPacket, &h, sizeof h, data, len);
    }
}

void host_reader(int node) {
    Peer& p = g_peers[node];
    uint8_t type;
    std::vector<uint8_t> f;
    while (read_frame(p.fd, type, f)) {
        if (type != kPacket || f.size() < sizeof(PacketHeader)) continue;
        PacketHeader h;
        std::memcpy(&h, f.data(), sizeof h);
        route(node, h, f.data() + sizeof h, uint32_t(f.size() - sizeof h));
    }
    p.alive = false;
    if (!g_stopping) {
        log("ldn: node %d left", node);
        ldn_link_remove_node(node);
        link_push_info();
    }
}

void host_accept() {
    while (!g_stopping) {
        const sock_t fd = accept(g_listen, nullptr, nullptr);
        if (fd == kBadSock) return;
        no_delay(fd);
        uint8_t type = 0;
        std::vector<uint8_t> f;
        int node = -1;
        if (read_frame(fd, type, f) && type == kJoin && f.size() >= 0x28) {
            std::lock_guard lk(g_peers_lock);
            node = ldn_link_add_node(f.data(), f.data() + 0x20, f.data() + 0x26);
        }
        if (node < 1 || node >= kMaxNodes) {
            const uint8_t h[5] = {kRefused, 0, 0, 0, 0};
            send_all(fd, h, 5);
            sock_close(fd);
            continue;
        }
        Peer& p = g_peers[node];
        if (p.reader.joinable()) p.reader.join();
        p.fd = fd;
        p.ip = ldn_node_ip(node);
        p.alive = true;
        const uint32_t id = uint32_t(node);
        send_frame(p, kWelcome, &id, 4);
        log("ldn: node %d joined", node);
        p.reader = std::thread(host_reader, node);
        link_push_info();
    }
}

void host_answer() {
    char in[32];
    std::vector<uint8_t> out(kMagicSize + kInfoSize);
    while (!g_stopping) {
        sockaddr_in from{};
        socklen_t fl = sizeof from;
        const int r = int(recvfrom(g_udp, in, sizeof in, 0, reinterpret_cast<sockaddr*>(&from), &fl));
        if (r < 0) {
            if (g_stopping) return;
            continue;  // Windows: an earlier answer's port closed (WSAECONNRESET)
        }
        if (r != int(kMagicSize) || std::memcmp(in, kProbe, kMagicSize)) continue;
        std::memcpy(out.data(), kAnswer, kMagicSize);
        if (!ldn_link_info(out.data() + kMagicSize)) continue;
        sendto(g_udp, reinterpret_cast<const char*>(out.data()), int(out.size()), 0,
               reinterpret_cast<const sockaddr*>(&from), sizeof from);
    }
}

void station_reader() {
    Peer& p = g_peers[0];
    uint8_t type;
    std::vector<uint8_t> f;
    while (read_frame(p.fd, type, f)) {
        if (type == kInfo && f.size() == kInfoSize) {
            ldn_link_set_info(f.data());
        } else if (type == kPacket && f.size() >= sizeof(PacketHeader)) {
            PacketHeader h;
            std::memcpy(&h, f.data(), sizeof h);
            const uint32_t n = uint32_t(f.size() - sizeof h);
            vsock_deliver(h.src_ip, h.src_port, h.dst_ip, h.dst_port, f.data() + sizeof h, n);
        }
    }
    p.alive = false;
    if (!g_stopping) {
        log("ldn: the link to the host ended");
        ldn_link_lost();
    }
}

bool resolve(const std::string& host, uint16_t port, sockaddr_in& out) {
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) || !res) return false;
    out = *reinterpret_cast<sockaddr_in*>(res->ai_addr);
    out.sin_port = htons(port);
    freeaddrinfo(res);
    return true;
}

std::vector<sockaddr_in> search_targets() {
    std::vector<sockaddr_in> v;
    const uint16_t port = link_port();
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    v.push_back(a);
    a.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    v.push_back(a);
    if (const char* e = std::getenv("NX_LDN_JOIN")) {
        std::string list = e;
        size_t i = 0;
        while (i <= list.size()) {
            size_t j = list.find(',', i);
            if (j == std::string::npos) j = list.size();
            std::string item = list.substr(i, j - i);
            uint16_t p = port;
            if (const size_t c = item.find(':'); c != std::string::npos) {
                p = uint16_t(std::atoi(item.c_str() + c + 1));
                item.resize(c);
            }
            if (!item.empty() && resolve(item, p, a)) v.push_back(a);
            i = j + 1;
        }
    }
    return v;
}

}  // namespace

void link_push_info() {
    uint8_t info[kInfoSize];
    if (!ldn_link_info(info)) return;
    for (int i = 1; i < kMaxNodes; i++)
        if (g_peers[i].alive) send_frame(g_peers[i], kInfo, info, uint32_t(kInfoSize));
}

void link_host_start() {
    net_init();
    g_stopping = false;
    g_role = kHost;
    const uint16_t port = link_port();
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    g_udp = socket(AF_INET, SOCK_DGRAM, 0);
    g_listen = socket(AF_INET, SOCK_STREAM, 0);
#ifndef _WIN32
    int one = 1;
    setsockopt(g_listen, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#endif
    if (g_udp == kBadSock || g_listen == kBadSock || bind(g_udp, reinterpret_cast<sockaddr*>(&a), sizeof a) ||
        bind(g_listen, reinterpret_cast<sockaddr*>(&a), sizeof a) || listen(g_listen, 8)) {
        log("ldn: cannot listen on port %u: this island will not be found", port);
        stop_socket(g_udp);
        stop_socket(g_listen);
        return;
    }
    log("ldn: hosting on port %u", port);
    g_udp_thread = std::thread(host_answer);
    g_accept_thread = std::thread(host_accept);
}

void link_stop() {
    g_stopping = true;
    stop_socket(g_udp);
    stop_socket(g_listen);
    if (g_udp_thread.joinable()) g_udp_thread.join();
    if (g_accept_thread.joinable()) g_accept_thread.join();
    for (Peer& p : g_peers) {
        p.alive = false;
        {
            std::lock_guard lk(p.tx);
            stop_socket(p.fd);
        }
        if (p.reader.joinable()) p.reader.join();
    }
    g_role = kNoRole;
    g_stopping = false;
}

int link_scan(uint8_t* out, int max, const uint8_t* filter, int max_results_size) {
    (void)max_results_size;
    net_init();
    const sock_t s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == kBadSock) return 0;
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char*>(&one), sizeof one);
    for (const sockaddr_in& a : search_targets())
        sendto(s, kProbe, int(kMagicSize), 0, reinterpret_cast<const sockaddr*>(&a), sizeof a);
    int count = 0;
    std::vector<uint8_t> in(kMagicSize + kInfoSize + 16);
    std::lock_guard lk(g_found_lock);
    g_found.clear();
    for (;;) {
        fd_set set;
        FD_ZERO(&set);
        FD_SET(s, &set);
        timeval tv{0, kScanMs * 1000};
        if (select(int(s) + 1, &set, nullptr, nullptr, &tv) <= 0) break;
        sockaddr_in from{};
        socklen_t fl = sizeof from;
        const int r = int(recvfrom(s, reinterpret_cast<char*>(in.data()), int(in.size()), 0,
                                   reinterpret_cast<sockaddr*>(&from), &fl));
        if (r != int(kMagicSize + kInfoSize) || std::memcmp(in.data(), kAnswer, kMagicSize)) continue;
        const uint8_t* info = in.data() + kMagicSize;
        if (std::memcmp(info, filter, 8)) continue;  // another game's
        bool seen = false;
        for (const Found& f : g_found) seen |= !std::memcmp(f.bssid, info + 0x20, 6);
        if (seen || count >= max) continue;
        Found f;
        std::memcpy(f.bssid, info + 0x20, 6);
        f.addr = from;
        g_found.push_back(f);
        std::memcpy(out + size_t(count) * kInfoSize, info, kInfoSize);
        count++;
    }
    sock_close(s);
    return count;
}

int link_join(const uint8_t* bssid, const uint8_t* name, const uint8_t* mac, const uint8_t* version, uint8_t* info) {
    sockaddr_in addr{};
    {
        std::lock_guard lk(g_found_lock);
        bool found = false;
        for (const Found& f : g_found)
            if (!std::memcmp(f.bssid, bssid, 6)) addr = f.addr, found = true;
        if (!found) return -1;
    }
    g_stopping = false;
    Peer& p = g_peers[0];
    if (p.reader.joinable()) p.reader.join();
    const sock_t fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == kBadSock) return -1;
    if (connect(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof addr)) {
        sock_close(fd);
        return -1;
    }
    no_delay(fd);
    p.fd = fd;
    uint8_t join[0x28];
    std::memcpy(join, name, 0x20);
    std::memcpy(join + 0x20, mac, 6);
    std::memcpy(join + 0x26, version, 2);
    int node = -1;
    uint8_t type = 0;
    std::vector<uint8_t> f;
    if (send_frame(p, kJoin, join, sizeof join)) {
        // The answer, then the first NetworkInfo: nothing else comes before the reader starts.
        if (read_frame(fd, type, f) && type == kWelcome && f.size() == 4) {
            std::memcpy(&node, f.data(), 4);
            while (read_frame(fd, type, f)) {
                if (type == kInfo && f.size() == kInfoSize) {
                    std::memcpy(info, f.data(), kInfoSize);
                    g_role = kStation;
                    p.alive = true;
                    p.reader = std::thread(station_reader);
                    return node;
                }
            }
        }
    }
    {
        std::lock_guard lk(p.tx);
        stop_socket(p.fd);
    }
    return -1;
}

void ldn_send(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port, const void* data, uint32_t len) {
    const PacketHeader h{src_ip, dst_ip, src_port, dst_port};
    if (g_role == kHost) return route(0, h, data, len);
    if (g_role != kStation) return;
    const bool all = dst_ip == ldn_broadcast_ip() || dst_ip == 0xFFFFFFFFu;
    if (all || dst_ip == ldn_own_ip()) vsock_deliver(src_ip, src_port, dst_ip, dst_port, data, len);  // (a broadcast too)
    if (dst_ip != ldn_own_ip()) send_frame(g_peers[0], kPacket, &h, sizeof h, data, len);
}

}  // namespace nx
