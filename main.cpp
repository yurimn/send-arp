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

int main(int argc, char* argv[]) {
	if (argc % 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	// Get my mac address
	struct ifreq ifr;
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	ioctl(s, SIOCGIFHWADDR, &ifr);
	Mac my_mac = Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
	printf("My Mac: %s\n", std::string(my_mac).c_str());

	// Get my ip address
	ioctl(s, SIOCGIFADDR, &ifr);
	Ip my_ip = Ip(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	printf("My IP: %s\n", std::string(my_ip).c_str());


	for(int i = 2; i < argc; i+=2) {
		char* sender_ip = argv[i];
		char* target_ip = argv[i+1];

		EthArpPacket packet;


	}
	
	// EthArpPacket packet;

	// packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	// packet.eth_.smac_ = Mac("00:00:00:00:00:00");
	// packet.eth_.type_ = htons(EthHdr::Arp);

	// packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	// packet.arp_.pro_ = htons(EthHdr::Ip4);
	// packet.arp_.hln_ = Mac::SIZE;
	// packet.arp_.pln_ = Ip::SIZE;
	// packet.arp_.op_ = htons(ArpHdr::Request);
	// packet.arp_.smac_ = Mac("00:00:00:00:00:00");
	// packet.arp_.sip_ = htonl(Ip("0.0.0.0"));
	// packet.arp_.tmac_ = Mac("ff:ff:ff:ff:ff:ff");
	// packet.arp_.tip_ = htonl(Ip("0.0.0.0"));

	// int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	// if (res != 0) {
	// 	fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	// }

	// pcap_close(handle);
}
