#ifndef ICMP_MAIN_H
#define ICMP_MAIN_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <iomanip>
#include <algorithm>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// Константы
const int DEFAULT_TIMEOUT = 1000;
const int DEFAULT_TTL = 128;
const int PACKET_SIZE = 1472;
const int MAX_HOPS = 30;

// Структуры данных
struct PingResult {
    std::string ip;
    int bytes;
    long time;
    int ttl;
    bool success;
    std::string error;
};

struct TraceRouteResult {
    int hop;
    std::string ip;
    long time;
    bool is_final;
};

typedef struct _IP_HEADER {
    unsigned char  ip_verlen;        // 4-bit version, 4-bit header length
    unsigned char  ip_tos;           // IP type of service
    unsigned short ip_totallength;   // Total length
    unsigned short ip_id;            // Unique identifier
    unsigned short ip_offset;        // Fragment offset
    unsigned char  ip_ttl;           // Time to live
    unsigned char  ip_protocol;      // Protocol (ICMP=1)
    unsigned short ip_checksum;      // Checksum
    unsigned int   ip_srcaddr;       // Source address
    unsigned int   ip_destaddr;      // Destination address
} IP_HEADER;

typedef struct _ICMP_HEADER {
    unsigned char  type;             // Type (8=echo request)
    unsigned char  code;             // Code (0)
    unsigned short checksum;         // Checksum
    unsigned short id;               // Identifier
    unsigned short seq;              // Sequence number
} ICMP_HEADER;

// Прототипы функций
void InitializeWinsock();
void CleanupWinsock();
HANDLE CreateIcmpHandle();
PingResult PingHost(const std::string& host, int timeout = DEFAULT_TIMEOUT, int ttl = DEFAULT_TTL);
void PrintPingResult(const PingResult& result);
void ContinuousPing(const std::string& host, int count = 4);
void MultiPing(const std::vector<std::string>& hosts);
std::vector<TraceRouteResult> TraceRoute(const std::string& host, int max_hops = MAX_HOPS);
void PrintTraceRoute(const std::vector<TraceRouteResult>& results);
void SmurfAttack(const std::string& victim, const std::string& broadcast, int count = 5);
void FloodSmurf(const std::string& victim, const std::string& broadcast, int count);
void PrintMenu();

// Вспомогательные функции
std::string GetErrorDescription(DWORD error);
sockaddr_in ResolveHost(const std::string& host);
std::string IpToString(DWORD ip);
DWORD StringToIp(const std::string& ipStr);
unsigned short CalculateChecksum(unsigned short* buffer, int size);

#endif//ICMP_MAIN_H
