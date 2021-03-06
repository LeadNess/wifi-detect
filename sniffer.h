#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/udp.h>
#include <ctime>
#include <string>
#include <iostream>
#include <fstream>
#include <array>
#include <map>
#include <set>

using std::ofstream;
using std::string;
using std::pair;
using std::set;
using std::cout;
using std::cerr;
using std::cin;
using std::endl;

using BSSID = std::array<uint8_t, 6>;
using MAC = std::array<uint8_t, 6>;

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

struct RadtapHeader {
    uint16_t useless;
    uint16_t length;
};



int writePcapFile(ofstream *fOut, int sock);