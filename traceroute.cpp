#include "main.h"

void trace_route(const std::string &host) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed: " << WSAGetLastError() << std::endl;
        return;
    }

    // Разрешение имени хоста
    sockaddr_in destAddr;
    memset(&destAddr, 0, sizeof(destAddr));
    destAddr.sin_family = AF_INET;

    if (inet_pton(AF_INET, host.c_str(), &destAddr.sin_addr) != 1) {
        addrinfo hints = {0}, *result = nullptr;
        hints.ai_family = AF_INET;

        if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0) {
            std::cerr << "getaddrinfo failed: " << WSAGetLastError() << std::endl;
            WSACleanup();
            return;
        }

        destAddr.sin_addr = ((sockaddr_in *)result->ai_addr)->sin_addr;
        freeaddrinfo(result);
    }

    std::cout << "Tracing route to " << host << " [" << inet_ntoa(destAddr.sin_addr) << "]" << std::endl;

    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE) {
        std::cerr << "IcmpCreateFile failed: " << GetLastError() << std::endl;
        WSACleanup();
        return;
    }

    char packet[32];
    memset(packet, 0, sizeof(packet));

    for (int ttl = 1; ttl <= 30; ttl++) {
        IP_OPTION_INFORMATION options;
        memset(&options, 0, sizeof(options));
        options.Ttl = ttl;
        options.Flags = IP_FLAG_DF; // Don't Fragment

        char replyBuffer[sizeof(ICMP_ECHO_REPLY) + sizeof(ICMP_ERROR_REPLY) + 32];
        DWORD replySize = sizeof(replyBuffer);

        DWORD startTime = GetTickCount();
        DWORD result = IcmpSendEcho2(
                hIcmp,
                nullptr,  // Event
                nullptr,  // APC Routine
                nullptr,  // APC Context
                destAddr.sin_addr.s_addr,
                packet,
                sizeof(packet),
                &options,
                replyBuffer,
                replySize,
                1000
        );

        DWORD elapsed = GetTickCount() - startTime;

        if (result == 0) {
            DWORD error = GetLastError();
            if (error == IP_REQ_TIMED_OUT) {
                std::cout << ttl << "\t*\t*\t* Request timed out." << std::endl;
                continue;
            } else {
                std::cerr << "IcmpSendEcho2 failed: " << error << std::endl;
                break;
            }
        }

        ICMP_ECHO_REPLY *reply = (ICMP_ECHO_REPLY *)replyBuffer;
        char ipStr[16];
        inet_ntop(AF_INET, &reply->Address, ipStr, sizeof(ipStr));

        if (reply->Status == IP_SUCCESS) {
            std::cout << ttl << "\t" << ipStr << "\t" << reply->RoundTripTime << " ms" << std::endl;
            std::cout << "Trace complete." << std::endl;
            break;
        } else if (reply->Status == IP_TTL_EXPIRED_TRANSIT) {
            std::cout << ttl << "\t" << ipStr << "\t" << elapsed << " ms" << std::endl;
        } else {
            std::cout << ttl << "\t" << ipStr << "\tError: " << reply->Status << std::endl;
        }
    }

    IcmpCloseHandle(hIcmp);
    WSACleanup();
}