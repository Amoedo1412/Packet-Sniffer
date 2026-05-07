#include <iostream>
#include <iomanip>
#include <winsock2.h>
#include <pcap.h>

// -------------------------------------------------------------------
// MOLDES DOS CABEÇALHOS
// -------------------------------------------------------------------

typedef struct eth_header {
    u_char dest_mac[6];
    u_char src_mac[6];
    u_short type;
} eth_header;

typedef struct ip_header {
    u_char  ver_ihl;
    u_char  tos;
    u_short tlen;
    u_short identification;
    u_short flags_fo;
    u_char  ttl;
    u_char  proto;
    u_short crc;
    u_char  saddr[4];
    u_char  daddr[4];
} ip_header;

typedef struct tcp_header {
    u_short sport;
    u_short dport;
    u_int   seq;
    u_int   ack;
    u_char  offset_res;
    u_char  flags;
    u_short win;
    u_short crc;
    u_short urp;
} tcp_header;

typedef struct udp_header {
    u_short sport;
    u_short dport;
    u_short len;
    u_short crc;
} udp_header;

// -------------------------------------------------------------------
// O INTERCETADOR FINAL COM GRAVAÇÃO
// -------------------------------------------------------------------
// Repara que o primeiro parâmetro agora é o nosso ficheiro de gravação (dumpfile)
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    
    // 1. GRAVAR NO FICHEIRO (A Magia acontece aqui)
    pcap_dump(dumpfile, header, pkt_data);

    // 2. IMPRIMIR NO ECRÃ (Para continuarmos a ver a ação)
    eth_header *eth = (eth_header *)pkt_data;
    
    if (ntohs(eth->type) == 0x0800) {
        ip_header *ip = (ip_header *)(pkt_data + 14);
        int ip_header_len = (ip->ver_ihl & 0x0f) * 4; 

        std::cout << "[GRAVADO] IP " << (int)ip->saddr[0] << "." << (int)ip->saddr[1] << "." << (int)ip->saddr[2] << "." << (int)ip->saddr[3];
        std::cout << " -> " << (int)ip->daddr[0] << "." << (int)ip->daddr[1] << "." << (int)ip->daddr[2] << "." << (int)ip->daddr[3];

        if (ip->proto == 6) {
            tcp_header *tcp = (tcp_header *)((u_char*)ip + ip_header_len);
            std::cout << " [TCP " << ntohs(tcp->sport) << " > " << ntohs(tcp->dport) << "]" << std::endl;
        } 
        else if (ip->proto == 17) {
            udp_header *udp = (udp_header *)((u_char*)ip + ip_header_len);
            std::cout << " [UDP " << ntohs(udp->sport) << " > " << ntohs(udp->dport) << "]" << std::endl;
        } else {
            std::cout << " [Outro]" << std::endl;
        }
    }
}

int main() {
    pcap_if_t *alldevs, *d;
    pcap_t *adhandle;
    pcap_dumper_t *dumpfile; // O nosso apontador para o ficheiro de gravação
    char errbuf[PCAP_ERRBUF_SIZE];
    int inum, i = 0;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) return 1;

    for (d = alldevs; d != nullptr; d = d->next) std::cout << ++i << ". " << (d->description ? d->description : d->name) << std::endl;
    if (i == 0) return 1;

    std::cout << "\n>>> Escolhe o numero da placa alvo (1-" << i << "): ";
    std::cin >> inum;
    if (inum < 1 || inum > i) return 1;

    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL) return 1;

    // ABRIR O FICHEIRO PARA GRAVAÇÃO
    dumpfile = pcap_dump_open(adhandle, "captura.pcap");
    if (dumpfile == NULL) {
        std::cerr << "Erro ao criar o ficheiro captura.pcap" << std::endl;
        return 1;
    }

    std::cout << "\n[*] Sniffer e Gravador Ativados! A guardar no ficheiro 'captura.pcap'." << std::endl;
    std::cout << "[*] Prima CTRL+C para parar a captura." << std::endl;
    pcap_freealldevs(alldevs);

    // Iniciar o loop, passando o 'dumpfile' para dentro do packet_handler
    pcap_loop(adhandle, -1, packet_handler, (unsigned char *)dumpfile);

    // Fechar o ficheiro corretamente
    pcap_dump_close(dumpfile);
    return 0;
}