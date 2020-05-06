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

using std::string;
using std::cout;
using std::cerr;
using std::cin;
using std::endl;

#define PCKT_LEN 4096

typedef struct pcap_hdr_t {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} ;

typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcaprec_hdr_t;

int FileDump(FILE *fd, int sock) {
    pcap_hdr_t file_header = { 0xa1b2c3d4, //magicnumber
                               2,4,
                               0,
                               0,
                               65535,
                               127  //Radiotap
    };

    char buff[4096];

    if (fd == nullptr) {
        perror("File open error:");
        return -1;
    }

    auto faildump = fwrite(&file_header, sizeof(pcap_hdr_t), 1, fd);

    if (faildump<= 0) {
        perror("File write error:");
        fclose(fd);
        return -1;
    }

    int count = 0;

    while (count < 100) {
        auto size = recv(sock, (void*)buff, sizeof(buff) - 1, 0);
        if (size == -1) {
            perror("recv error:");
            fclose(fd);
            return -1;
        }

        struct timeval time1;
        struct timezone tv2 = {	0, 0 };

        gettimeofday(&time1, &tv2);
        pcaprec_hdr_t packet_header = {
                (uint32_t)time1.tv_sec,
                (uint32_t)time1.tv_usec,
                (uint32_t)size,
                (uint32_t)size
        };

        faildump = fwrite(&packet_header, sizeof(pcaprec_hdr_t), 1, fd);

        if (faildump<= 0) {
            perror("File write error:");
            fclose(fd);
            return -1;
        }

        faildump = fwrite(&buff, size, 1, fd);

        if (faildump<= 0) {
            perror("File write error:");
            fclose(fd);
            return -1;
        }

        count++;
    }
    fclose(fd);

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


    sockaddr_ll sll;
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
    FILE *fd = fopen(fname, "w");

    FileDump(fd, sock);
    close(sock);
    return 0;
}