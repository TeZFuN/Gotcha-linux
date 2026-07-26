// g++ -O2 intercept.cpp -o intercept -lpcap -std=c++11
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <getopt.h>

volatile int stop_capture = 0;

void handle_sigint(int sig) {
    stop_capture = 1;
}

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth = (struct ether_header *)packet;
    struct ip *ip = NULL;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    const char *proto = "Unknown";
    int len = pkthdr->len;

    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        ip = (struct ip *)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &ip->ip_src, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip->ip_dst, dst_ip, INET_ADDRSTRLEN);

        if (ip->ip_p == IPPROTO_TCP) {
            proto = "TCP";
        } else if (ip->ip_p == IPPROTO_UDP) {
            proto = "UDP";
        } else if (ip->ip_p == IPPROTO_ICMP) {
            proto = "ICMP";
        } else {
            proto = "IP";
        }
    } else if (ntohs(eth->ether_type) == ETHERTYPE_ARP) {
        proto = "ARP";
        strcpy(src_ip, "N/A");
        strcpy(dst_ip, "N/A");
    } else {
        proto = "Non-IP";
        strcpy(src_ip, "N/A");
        strcpy(dst_ip, "N/A");
    }

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);

    printf("[%s] %s -> %s, proto=%s, len=%d\n", time_str, src_ip, dst_ip, proto, len);
    fflush(stdout);
}

int main(int argc, char *argv[]) {
    char *iface = NULL;
    int count = -1;
    char *filter = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "i:c:")) != -1) {
        switch (opt) {
            case 'i': iface = optarg; break;
            case 'c': count = atoi(optarg); break;
            default: break;
        }
    }

    if (iface == NULL || count < 0) {
        fprintf(stderr, "Usage: %s -i <interface> -c <count> [filter]\n", argv[0]);
        return 1;
    }

    if (optind < argc) {
        filter = argv[optind];
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(iface, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Interface doesn't support Ethernet\n");
        pcap_close(handle);
        return 1;
    }

    if (filter != NULL) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return 1;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return 1;
        }
        pcap_freecode(&fp);
    }

    signal(SIGINT, handle_sigint);

    fprintf(stderr, "Capturing on %s, filter='%s', count=%d\n", iface, filter ? filter : "none", count);
    fflush(stderr);

    if (count > 0) {
        pcap_loop(handle, count, packet_handler, NULL);
    } else {
        while (!stop_capture) {
            pcap_dispatch(handle, 1, packet_handler, NULL);
        }
    }

    pcap_close(handle);
    return 0;
}