#include <iostream>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


void print_hex(const u_char* data, int data_len) {
    // Print hex
    for (int i = 0; i < data_len; i++) {
        printf("%02X ", data[i]);
    }
}

void process_packet(const u_char* packet, int packet_len) {
    // Extract Ethernet header
    struct ether_header* ethernet_header = (struct ether_header*)(packet);
    int ethernet_header_len = sizeof(struct ether_header);

    // Check if it's an IP packet
    if (ntohs(ethernet_header->ether_type) != ETHERTYPE_IP) {
        return;
    }

    // Extract IP header
    struct ip* ip_header = (struct ip*)(packet + ethernet_header_len);
    int ip_header_len = ip_header->ip_hl * 4;

    // Check if it's a TCP packet
    if (ip_header->ip_p != IPPROTO_TCP) {
        return;
    }

    // Extract TCP header
    struct tcphdr* tcp_header = (struct tcphdr*)(packet + ethernet_header_len + ip_header_len);
    int tcp_header_len = tcp_header->th_off * 4;

    // Check if it's a SSL (HTTPS) packet (assuming source port 443)
    if (ntohs(tcp_header->th_sport) != 443) {
        return;
    }

    // Extract source IP and port
    char source_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip_str, INET_ADDRSTRLEN);
    uint16_t source_port = ntohs(tcp_header->th_sport);

    // Extract SSL payload (TCP data)
    const u_char* ssl_payload = packet + ethernet_header_len + ip_header_len + tcp_header_len;
    int ssl_payload_len = packet_len - ethernet_header_len - ip_header_len - tcp_header_len;

    // Print SSL payload in hexadecimal format
    print_hex(ssl_payload, ssl_payload_len);
    printf("/%s:%d\n", source_ip_str, source_port);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>" << std::endl;
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap_handle = pcap_open_offline(argv[1], errbuf);
    if (!pcap_handle) {
        std::cerr << "Error opening pcap file: " << errbuf << std::endl;
        return 1;
    }

    struct pcap_pkthdr header;
    const u_char* packet;

    while ((packet = pcap_next(pcap_handle, &header))) {
        process_packet(packet, header.len);
    }

    pcap_close(pcap_handle);
    return 0;
}
