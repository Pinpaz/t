#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

struct ethhdr
{

    unsigned char ether_dhost[6];

    unsigned char ether_shost[6];

    unsigned short ether_ty;

};

struct iphdr{

    unsigned char Version : 4;

    unsigned char IHL : 4;

    unsigned char TOS;

    u_short TotalLen;

    unsigned short Iden;

    unsigned char Flags1 : 1;

    unsigned char Flags2 : 1;

    unsigned char Flags3 : 1;

    unsigned int FO : 13;

    unsigned char TTL;

    unsigned char Protocal;

    unsigned short HeaderCheck;

    struct in_addr SrcAdd;

    struct in_addr DstAdd;
};

struct tcphdr{

    unsigned short SrcPort;

    unsigned short DstPort;

    unsigned int SN;

    unsigned int AN;

    unsigned char Offset : 4;

    unsigned char Reserved : 4;

    unsigned char FlagsC : 1;

    unsigned char FlagsE : 1;

    unsigned char FlagsU : 1;

    unsigned char FlagsA : 1;

    unsigned char FlagsP : 1;

    unsigned char FlagsR : 1;

    unsigned char FlagsS : 1;

    unsigned char FlagsF : 1;

    unsigned short Window;

    unsigned short Check;

    unsigned short UP;

};

struct data{
    char payroad[1500];
};


void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
    struct ethhdr *eth = (struct ethhdr *)packet;
   printf("src-mac : %02x:%02x:%02x:%02x:%02x:%02x\n",eth -> ether_shost[0],eth -> ether_shost[1],eth -> ether_shost[2],eth -> ether_shost[3],eth -> ether_shost[4], eth -> ether_shost[5]);


   printf("des-mac : %02x:%02x:%02x:%02x:%02x:%02x\n",eth -> ether_dhost[0],eth -> ether_dhost[1],eth -> ether_dhost[2],eth -> ether_dhost[3],eth -> ether_dhost[4], eth -> ether_dhost[5]);

    if (ntohs(eth -> ether_ty) == 0x0800){
    struct iphdr * ip = (struct iphdr *)
                           (packet + sizeof(struct ethhdr)); 

    printf("목적지ip: %s\n", inet_ntoa(ip->SrcAdd));   
    printf("도착지ip: %s\n", inet_ntoa(ip->DstAdd));    

    struct tcphdr * tcp = (struct tcphdr *)
                            (packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
//printf("Destination port number       : %d\n",ntohs(th->dport));
    printf("목적지port: %d\n", ntohs(tcp -> SrcPort));
    printf("도착지port: %d\n", ntohs(tcp -> DstPort));

    struct data * texxxt = (struct data *)
                        (packet + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr));
    
    printf("메세지: %s\n\n\n",texxxt -> payroad);

    switch (ip -> Protocal)
    {
    case IPPROTO_UDP:
        printf("protocol: UDP\n");
        return;
    
    case IPPROTO_TCP:
        printf("protocol: TCP\n");
        return;

    case IPPROTO_ICMP:
        printf("protocol: ICMP\n");
        return;

    default:
        printf("protocol: other\n");
        return;
    }

}
}
                           

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("bridge101", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }


  /// 루프를 통해 패킷을 받아옵니다.
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   
  return 0;
}