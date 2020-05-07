#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include "sniffer.h"


int main(int argc, char* argv[]) {
    string ifName;
    if (argc != 2) {
        cerr << "Usage: <ifacename> " << endl;
        return -1;
    } else {
        ifName = string(argv[1]);
    }

    int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        cerr << "Error on opening socket: " << sock << endl;
        return -1;
    }

    ifreq ifRequest{};
    memset(&ifRequest, 0, sizeof(ifRequest));
    strncpy((char *) ifRequest.ifr_name, ifName.c_str(), IFNAMSIZ);
    int rc = ioctl(sock, SIOCGIFINDEX, &ifRequest);
    if (rc < 0) {
        cerr << "Invalid interface name: " << ifName << endl;
        return -1;
    }

    int ifIndex = ifRequest.ifr_ifindex;
    memset(&ifRequest, 0, sizeof(ifRequest));
    strncpy((char *) ifRequest.ifr_name, ifName.c_str(), IFNAMSIZ);
    ifRequest.ifr_ifindex = ifIndex;

    rc = ioctl(sock, SIOCGIFHWADDR, &ifRequest);
    if (rc < 0) {
        cerr << "Error on 'SIOCGIFHWADDR'" << endl;
        return -1;
    }

    int arpType = ifRequest.ifr_hwaddr.sa_family;
    if (arpType != 803) {
        cerr << "Interface doesn't support IEEE 802.11 radiotap" << endl;
        return -1;
    }

    sockaddr_ll sll{};
    memset(&sll, 0, sizeof(sll));
    memset(&ifRequest, 0, sizeof(ifRequest));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifIndex;
    sll.sll_protocol = htons(ETH_P_ALL);
    rc = bind(sock, (struct sockaddr *) &sll, sizeof(sll));
    if (rc < 0) {
        cerr << "Error on bind to socket" << endl;
        return -1;
    }

    string pcapFileName = "capture.pcap";
    ofstream fOut(pcapFileName);
    if (!fOut.is_open()) {
        cerr << "Error on opening file: " << pcapFileName << endl;
        return -1;
    }

    writePcapFile(&fOut, sock);
    close(sock);
    fOut.close();
    return 0;
}