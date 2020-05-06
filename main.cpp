#include <pcap.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <ctime>
#include <string>
#include <iostream>
#include <fstream>

using std::ofstream;
using std::string;
using std::cout;
using std::cerr;
using std::cin;
using std::endl;


struct PcapHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct PcapRecHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

int writePcapFile(ofstream *fout, int sock) {
    PcapHeader fileHeader = {0xa1b2c3d4,
                             2,
                             4,
                             0,
                             0,
                             65535,
                             127
    };
    fout->write(reinterpret_cast<const char *>(&fileHeader), sizeof(PcapHeader));
    char buff[4096];
    for(;;) {
        int size = recv(sock, (void*)buff, sizeof(buff) - 1, 0);
        if (size == -1) {
            cerr << "Error on recv" << endl;
            fout->close();
            return -1;
        }
        timeval timeVal{};
        struct timeone timeOne = {0, 0};

        gettimeofday(&timeVal, &timeOne);
        PcapRecHeader packetHeader = {
                (uint32_t)timeVal.tv_sec,
                (uint32_t)timeVal.tv_usec,
                (uint32_t)size,
                (uint32_t)size
        };
        fout->write(reinterpret_cast<const char *>(&packetHeader), sizeof(PcapRecHeader));
        fout->write(reinterpret_cast<const char *>(&buff), size);
    }
}


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

    ifreq ifr{};
    memset(&ifr, 0, sizeof(ifr));
    strncpy((char *) ifr.ifr_name, ifName.c_str(), IFNAMSIZ);
    int rc = ioctl(sock, SIOCGIFINDEX, &ifr);
    if (rc < 0) {
        cerr << "Invalid interface name: " << ifName << endl;
        return -1;
    }

    int ifIndex = ifr.ifr_ifindex;
    memset(&ifr, 0, sizeof(ifr));
    strncpy((char *) ifr.ifr_name, ifName.c_str(), IFNAMSIZ);
    ifr.ifr_ifindex = ifIndex;

    rc = ioctl(sock, SIOCGIFHWADDR, &ifr);
    if (rc < 0) {
        cerr << "Error on 'SIOCGIFHWADDR'" << endl;
        return -1;
    }

    int arpType = ifr.ifr_hwaddr.sa_family;
    if (arpType != 803) {
        cerr << "Interface doesn't support IEEE 802.11 radiotap" << endl;
        return -1;
    }


    sockaddr_ll sll{};
    memset(&sll, 0, sizeof(sll));
    memset(&ifr, 0, sizeof(ifr));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifIndex;
    sll.sll_protocol = htons(ETH_P_ALL);
    rc = bind(sock, (struct sockaddr *) &sll, sizeof(sll));
    if (rc < 0) {
        cerr << "Error on bind to socket" << endl;
        return -1;
    }

    string pcapFileName = "capture.pcap";
    ofstream fout(pcapFileName);
    if (!fout.is_open()) {
        cerr << "Error on opening file: " << pcapFileName << endl;
        return -1;
    }

    writePcapFile(&fout, sock);
    close(sock);
    fout.close();
    return 0;
}