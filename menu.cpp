#include "main.h"

void menuPing () {
    std::string host;
    std::cout << "Введите IP или имя хоста: ";
    std::getline(std::cin, host);
    PingResult result = PingHost(host);
    PrintPingResult(result);
}

void menuContPing () {
    std::string host;
    int count;
    std::cout << "Введите IP или имя хоста: ";
    std::getline(std::cin, host);
    std::cout << "Введите количество запросов (0 для бесконечного): ";
    std::cin >> count;
    std::cin.ignore();
    ContinuousPing(host, count);
}

void menuMultiPing () {
    std::cout << "Введите IP/имена хостов через пробел: ";
    std::string input;
    std::getline(std::cin, input);

    std::vector<std::string> hosts;
    size_t pos = 0;
    while ((pos = input.find(' ')) != std::string::npos) {
        hosts.push_back(input.substr(0, pos));
        input.erase(0, pos + 1);
    }
    if (!input.empty()) hosts.push_back(input);

    MultiPing(hosts);
}

void menuTraceroute () {
    std::string host;
    std::cout << "Введите IP или имя хоста для трассировки: ";
    std::getline(std::cin, host);
    auto trace = TraceRoute(host);
    PrintTraceRoute(trace);
}

void menuSmurfAttack(){
    std::string victim, broadcast;
    int count;
    std::cout << "ВНИМАНИЕ: Это демонстрационная функция!\n";
    std::cout << "Введите IP жертвы: ";
    std::getline(std::cin, victim);
    std::cout << "Введите broadcast адрес сети: ";
    std::getline(std::cin, broadcast);
    std::cout << "Введите количество пакетов: ";
    std::cin >> count;
    std::cin.ignore();
    FloodSmurf(victim, broadcast, count);
//    SmurfAttack(victim, broadcast, count);
}

void PrintMenu() {
    std::cout << "\nICMP Network Tool\n";
    std::cout << "1. Ping хоста\n";
    std::cout << "2. Непрерывный ping\n";
    std::cout << "3. Многопоточный ping\n";
    std::cout << "4. Traceroute\n";
    std::cout << "5. Smurf-атака\n";
    std::cout << "0. Выход\n";
    std::cout << "Выберите действие: ";
}

void menu(){
    int choice;
    do {
        PrintMenu();
        std::cin >> choice;
        std::cin.ignore();

        switch (choice) {
            case 1: {
                menuPing();
                break;
            }
            case 2: {
                menuContPing();
                break;
            }
            case 3: {
                menuMultiPing();
                break;
            }
            case 4: {
                menuTraceroute();
                break;
            }
            case 5: {
                menuSmurfAttack();
                break;
            }
            case 0:
                std::cout << "Выход...\n";
                break;
            default:
                std::cout << "Неверный выбор!\n";
        }
    } while (choice != 0);
}