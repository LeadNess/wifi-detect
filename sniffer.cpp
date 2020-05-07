#include <thread>
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

    std::map<BSSID, set<MAC>> mapTable;

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

        auto packet = (PcapRecHeader*)buff;
        cout << "Len = "<< packet->incl_len;
        auto rtpHdr = (RadtapHeader*)buff;
        int rtpLen = rtpHdr->length;
        uint8_t type = buff[rtpLen];
        cout << ", radtap type = " << type << ", radtap len = " << rtpLen << endl;
        bool assResponse = false;
        bool managmentFrame = false;

        if (((type & (1 << 3)) >> 3 == 1 && (type & (1 << 2)) >> 2 == 0) ||
            ((type & (1 << 3)) >> 3 == 0 && (type & (1 << 2)) >> 2 == 0	&&
            (type & (1 << 4)) >> 4 == 1 && (type & (1 << 5)) >> 5 == 0 &&
            (type & (1 << 6)) >> 6 == 0 && (type &( 1 << 7)) >> 7 == 0)) {
            if ((type & (1 << 3)) >> 3 == 0 && (type & (1 << 2)) >> 2 == 0 &&
                (type & (1 << 4)) >> 4 == 1 && (type & (1 << 5)) >> 5 == 0 &&
                (type & (1 << 6)) >> 6 == 0 && (type & (1 << 7)) >> 7 == 0) {

                uint8_t byte1, byte2;
                byte1 = buff[rtpLen + 24 + 2];
                byte2 = buff[rtpLen + 24 + 3];
                if (byte1 != 0x00 || byte2 != 0x00) {
                    continue;
                } else {
                    assResponse = true;
                }
            }
            uint8_t flags = buff[rtpLen + 1];
            int tods = (int)(flags & 1);
            int fromds = (int)((flags & (1 << 1)) >> 1);
            cout << "tods = "<< tods << endl;
            cout << "fromds = "<< fromds << endl;

            MAC addr1;
            MAC addr2;
            MAC addr3;
            MAC addr4;
            MAC broadcast;

            if (tods == 0 && fromds == 0) {
                for (int j = 0; j < 6; j++) {
                    addr1[j] = buff[rtpLen + 4 + j];
                }
                for (int j = 0; j < 6; j++) {
                    addr2[j] = buff[rtpLen + 10 + j];
                }
                for (int j = 0; j < 6; j++) {
                    addr3[j] = buff[rtpLen + 16 + j];
                }

                auto it = mapTable.find(addr3);
                if (it != mapTable.end()) {
                    if (addr1 != broadcast) {
                        it->second.insert(addr1);
                    }
                    if (addr2 != broadcast && !managmentFrame) {
                        it->second.insert(addr2);
                    }
                }
                else {
                    set<MAC> setMAC;
                    mapTable.insert(pair<BSSID,set<MAC>>(addr3, setMAC));
                    it = mapTable.find(addr3);
                    if (addr1 != broadcast) {
                        it->second.insert(addr1);
                    }
                    if (addr2 != broadcast && !managmentFrame) {
                        it->second.insert(addr2);
                    }
                }
            }
            if (tods == 0 && fromds == 1) {
                for (int j = 0; j < 6; j++) {
                    addr1[j] = buff[rtpLen + 4 + j];
                }
                for (int j = 0; j < 6; j++) {
                    addr2[j] = buff[rtpLen + 10 + j];
                }
                for (int j = 0; j < 6; j++) {
                    addr3[j] = buff[rtpLen + 16 + j];
                }
                auto it = mapTable.find(addr2);
                if (it != mapTable.end()) {
                    if(addr1!=broadcast) {
                        it->second.insert(addr1);
                    }
                }
                else {
                    set<MAC> setMAC;
                    mapTable.insert(pair<BSSID,set<MAC>>(addr2, setMAC));
                    it = mapTable.find(addr2);
                    if (addr1 != broadcast) {
                        it->second.insert(addr1);
                    }
                }
            }
            if (tods == 1 && fromds == 0) {
                for (int j = 0; j < 6; j++) {
                    addr1[j] = buff[rtpLen + 4 + j];
                }
                for (int j = 0; j<6; j++) {
                    addr2[j] = buff[rtpLen + 10 + j];
                }
                for (int j = 0; j < 6; j++) {
                    addr3[j] = buff[rtpLen + 16 + j];
                }
                auto it = mapTable.find(addr1);
                if (it != mapTable.end()) {
                    if (addr2 != broadcast) {
                        it->second.insert(addr2);
                    }
                }
                else {
                    set<MAC> setMAC;
                    mapTable.insert(pair<BSSID,set<MAC>>(addr1, setMAC));
                    it = mapTable.find(addr1);
                    if (addr2 != broadcast)
                        it->second.insert(addr2);
                }
            }
            if (tods == 1 && fromds == 1) {
                for (int j = 0; j < 6; j++) {
                    addr1[j] = buff[rtpLen + 4 + j];
                }
                for (int j = 0; j < 6; j++) {
                    addr2[j] = buff[rtpLen + 10 + j];
                }
                for (int j = 0; j < 6; j++) {
                    addr3[j] = buff[rtpLen + 16 + j];
                }
                for (int j = 0; j < 6; j++) {
                    addr4[j] = buff[rtpLen + 24 + j];
                }
                auto it = mapTable.find(addr2);
                if (it != mapTable.end()) {
                    if (addr1 != broadcast) {
                        it->second.insert(addr1);
                    }
                }
                else {
                    set<MAC> setMAC;
                    mapTable.insert(pair<BSSID,set<MAC>>(addr2, setMAC));
                    it = mapTable.find(addr2);
                    if (addr1 != broadcast) {
                        it->second.insert(addr1);
                    }
                }
            }
        }
    }
}