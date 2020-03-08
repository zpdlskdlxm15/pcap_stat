#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <map>
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
using namespace std;

void usage() {
  printf("syntax: pcap_stat <sample.pcap>\n");
}

typedef struct {
    uint8_t DMac[6];
    uint8_t SMac[6];
    uint16_t Type;
} EthernetInfo;

typedef struct {
    uint8_t VERIHL;
    uint8_t TypeofService;
    uint16_t TotalLength;
    uint16_t Identifier;
    uint16_t FlagsandFragment;
    uint8_t TimetoLive;
    uint8_t Protocol;
    uint16_t HeaderChecksum;
    uint32_t SIp;
    uint32_t DIp;
} Ipv4Info;

typedef struct {
    uint16_t SPort;
    uint16_t DPort;
    uint32_t SequenceNum;
    uint32_t AcknowledgementNum;
    uint8_t HeaderLength; 
    uint8_t Flag;
    uint16_t WindowSize;
    uint16_t Checksum;
    uint16_t UrgentPointer;
} TCPInfo;

typedef struct {
    uint32_t SPacketCnt;
    uint32_t DPacketCnt;
    uint32_t Sbyte;
    uint32_t Dbyte;
} PacketInfo;


typedef struct MAC{
    uint8_t mac[6];

    bool operator <(const MAC& t) const {
        return memcmp(mac, t.mac, sizeof(mac)) < 0;
    }
} MAC;

typedef struct MAC_CONV{
    uint8_t SMac[6];
    uint8_t DMac[6];
    bool operator <(const MAC_CONV& t) const {
        if (memcmp(SMac, t.SMac, sizeof(SMac)) != 0){
            return memcmp(SMac, t.SMac, sizeof(SMac)) < 0;
        } else {
            return memcmp(DMac, t.DMac, sizeof(DMac)) < 0;
        }
    }
} MAC_CONV;

void packet_info(struct pcap_pkthdr *header, const u_char *packet);



void map_ip_endpoint(map<uint32_t, PacketInfo> &ip_endpoint, Ipv4Info* v4Info) {
    if(ip_endpoint.find(ntohl(v4Info->SIp)) == ip_endpoint.end()) { 
        ip_endpoint[ntohl(v4Info->SIp)].SPacketCnt = 1; 
        ip_endpoint[ntohl(v4Info->SIp)].DPacketCnt = 0;
        ip_endpoint[ntohl(v4Info->SIp)].Sbyte = ntohs(v4Info->TotalLength) + 14;
        ip_endpoint[ntohl(v4Info->SIp)].Dbyte = 0;
    } else {
        ip_endpoint[ntohl(v4Info->SIp)].SPacketCnt++;
        ip_endpoint[ntohl(v4Info->SIp)].Sbyte += ntohs(v4Info->TotalLength) + 14;
    }

    if(ip_endpoint.find(ntohl(v4Info->DIp)) == ip_endpoint.end()) {
        ip_endpoint[ntohl(v4Info->DIp)].SPacketCnt = 0;
        ip_endpoint[ntohl(v4Info->DIp)].DPacketCnt = 1;
        ip_endpoint[ntohl(v4Info->DIp)].Sbyte = 0;
        ip_endpoint[ntohl(v4Info->DIp)].Dbyte = ntohs(v4Info->TotalLength) + 14;
    } else {
        ip_endpoint[ntohl(v4Info->DIp)].DPacketCnt++;
        ip_endpoint[ntohl(v4Info->DIp)].Dbyte += ntohs(v4Info->TotalLength) + 14;
    }
}

void map_ip_conversation(map<uint64_t, PacketInfo> &ip_conversation, Ipv4Info* v4Info) {

    uint64_t conversation;
    uint32_t A, B;

    A = ntohl(v4Info->SIp); 
    B = ntohl(v4Info->DIp); 
    conversation = (uint64_t(A) << 32) + B;


    if(ip_conversation.find(conversation) == ip_conversation.end()) {
        ip_conversation[conversation].SPacketCnt = 0;
        ip_conversation[conversation].DPacketCnt = 0;
        ip_conversation[conversation].Sbyte = 0;
        ip_conversation[conversation].Dbyte = 0;
    }

    if(A < B) {
        ip_conversation[conversation].SPacketCnt++;
        ip_conversation[conversation].Sbyte += ntohs(v4Info->TotalLength) + 14;
    } else if (A > B){
        ip_conversation[conversation].DPacketCnt++;
        ip_conversation[conversation].Dbyte += ntohs(v4Info->TotalLength) + 14;
    } else {}
}

void print_endpoint_map_ip(map<uint32_t, PacketInfo> &ip_endpoint) {
    printf("\n");
    printf("\t\t\t\tStatistics Endpoints IPv4\n");
    printf("========================================================================================\n");
    printf("Address\t\tPackets\tBytes\tTx Packets\tTx Bytes\tRx Packets\tRx Bytes\n");

    for(map<uint32_t, PacketInfo>::iterator it = ip_endpoint.begin(); it!= ip_endpoint.end(); it++) {
        uint32_t hexIP = it->first;
        printf("%d.%d.%d.%d\t", hexIP >> 24, (hexIP >> 16) & 0xff, (hexIP >> 8) & 0xff, hexIP & 0xff);

        printf("%d\t", it->pair::second.SPacketCnt + it->pair::second.DPacketCnt); 
        printf("%d\t", it->pair::second.Sbyte + it->pair::second.Dbyte); 
        printf("%d\t\t", it->pair::second.SPacketCnt); 
        printf("%d\t\t", it->pair::second.Sbyte); 
        printf("%d\t\t", it->pair::second.DPacketCnt); 
        printf("%d\t\t\n", it->pair::second.Dbyte); 
    }
}

void print_conversation_map_ip(map<uint64_t, PacketInfo> &ip_conversation) {
    printf("\n");
    printf("\t\t\t\tConversations Endpoints IPv4\n");
    printf("========================================================================================\n");
    printf("Address A\tAddress B\tPackets\tBytes\tPackets A->B\tBytes A->B\tPackets B->A\tBytes B->A\n");

    for(map<uint64_t, PacketInfo>::iterator it = ip_conversation.begin(); it != ip_conversation.end(); it++) {
        uint64_t hexIP = it->first;

        printf("%u.%u.%u.%u\t", (hexIP >> 56) & 0xff, (hexIP >> 48) & 0xff, (hexIP >> 40) & 0xff, (hexIP >> 32) & 0xff);
        printf("%u.%u.%u.%u\t", (hexIP >> 24) & 0xff, (hexIP >> 16) & 0xff, (hexIP >> 8) & 0xff, hexIP & 0xff);

        printf("%d\t", it->pair::second.SPacketCnt + it->pair::second.SPacketCnt); 
        printf("%d\t", it->pair::second.Sbyte+it->pair::second.Dbyte); 
        printf("%d\t\t", it->pair::second.SPacketCnt); 
        printf("%d\t\t", it->pair::second.Sbyte); 
        printf("%d\t\t", it->pair::second.DPacketCnt); 
        printf("%d\t\t\t\n", it->pair::second.Dbyte); 
    }
}


void map_mac_endpoint(map<MAC, PacketInfo> &mac_endpoint, EthernetInfo* EInfo, Ipv4Info* v4Info) {

    // if(mac_endpoint.find(EInfo->SMac) == mac_endpoint.end()) // no matching member function for call to 'find'

}



int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_offline(argv[1], errbuf);
  if (handle == NULL) {
      fprintf(stderr, "couldn't open file %s: %s\n", argv[1], errbuf);
      return -1;
  }


  map<uint32_t, PacketInfo> ip_endpoint;   
  map<uint64_t, PacketInfo> ip_conversation;   
  map<MAC, PacketInfo> mac_endpoint;  
  map<MAC_CONV, PacketInfo> mac_conversation; 

  while(handle != NULL){
      struct pcap_pkthdr* header;
      const u_char* packet;
      int res = pcap_next_ex(handle, &header, &packet);
      if (res == 0) continue;
      if (res == -1 || res == -2) break;

      int v4InfoSize;
      EthernetInfo* EInfo = const_cast<EthernetInfo*>(reinterpret_cast<const EthernetInfo*>(packet)); //(EthernetInfo*)packet;
      Ipv4Info* v4Info = const_cast<Ipv4Info*>(reinterpret_cast<const Ipv4Info*>(packet+sizeof(EthernetInfo))); 
      v4InfoSize = (v4Info->VERIHL & 0x0F) * 4;

      // TCPInfo* tcpInfo = const_cast<TCPInfo*>(reinterpret_cast<const TCPInfo*>(packet+sizeof(EthernetInfo)+sizeof(Ipv4Info)));

      if(ntohs(EInfo->Type) == 0x0800) {
        map_ip_endpoint(ip_endpoint, v4Info);
        map_ip_conversation(ip_conversation, v4Info);


        map_mac_endpoint(mac_endpoint, EInfo, v4Info);
        map_mac_conversation(mac_conversation, EInfo, v4Info);
      }
  }
  print_endpoint_map_ip(ip_endpoint);
  print_conversation_map_ip(ip_conversation);
  pcap_close(handle);
  return 0;
}


