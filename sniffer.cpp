#include "sniffer.h"


int writePcapFile(ofstream *fOut, int sock) {
    PcapHeader fileHeader = {0xa1b2c3d4,
                             2,
                             4,
                             0,
                             0,
                             65535,
                             127
    };
    fOut->write(reinterpret_cast<const char *>(&fileHeader), sizeof(PcapHeader));
    char buff[4096];
    for(;;) {
        int size = recv(sock, (void*)buff, sizeof(buff) - 1, 0);
        if (size == -1) {
            cerr << "Error on recv" << endl;
            fOut->close();
            return -1;
        }
        timeval timeVal{};
        struct timezone timeZone = {0, 0};

        gettimeofday(&timeVal, &timeZone);
        PcapRecHeader packetHeader = {
                (uint32_t)timeVal.tv_sec,
                (uint32_t)timeVal.tv_usec,
                (uint32_t)size,
                (uint32_t)size
        };
        fOut->write(reinterpret_cast<const char *>(&packetHeader), sizeof(PcapRecHeader));
        fOut->write(reinterpret_cast<const char *>(&buff), size);
    }
}