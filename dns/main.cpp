#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
bool IsRunningAsAdmin() {
    BOOL isMember = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    if (AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &AdministratorsGroup)) {
        CheckTokenMembership(NULL, AdministratorsGroup, &isMember);
        FreeSid(AdministratorsGroup);
    }
    return isMember;
}
std::vector<std::string> GetActiveInterfaces() {
    std::vector<std::string> result;
    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);

    if (pAddresses == NULL) return result;

    if (GetAdaptersAddresses(AF_INET, 0, NULL, pAddresses, &outBufLen) == NO_ERROR) {
        for (PIP_ADAPTER_ADDRESSES pCurr = pAddresses; pCurr != NULL; pCurr = pCurr->Next) {
            if (pCurr->OperStatus == IfOperStatusUp) {
                std::wstring ws(pCurr->FriendlyName);
                std::string name(ws.begin(), ws.end());
                result.push_back(name);
            }
        }
    }
    free(pAddresses);
    return result;
}
void EnableDNS(const std::vector<std::string>& interfaces, const std::string& dns1, const std::string& dns2) {
    for (const auto& iface : interfaces) {
        std::string cmd1 = "netsh interface ipv4 set dns name=\"" + iface + "\" static " + dns1 + " primary";
        std::string cmd2 = "netsh interface ipv4 add dns name=\"" + iface + "\" " + dns2 + " index=2";
        system(cmd1.c_str());
        system(cmd2.c_str());
        std::cout << "[✔] DNS включен для интерфейса: " << iface << std::endl;
    }
}
void DisableDNS(const std::vector<std::string>& interfaces) {
    for (const auto& iface : interfaces) {
        std::string cmd = "netsh interface ipv4 set dns name=\"" + iface + "\" dhcp";
        system(cmd.c_str());
        std::cout << "[✖] DNS сброшен на автоматический для интерфейса: " << iface << std::endl;
    }
}

int main() {
	setlocale(LC_ALL, "Russian");
    if (!IsRunningAsAdmin()) {
        MessageBoxA(NULL, "Запусти программу от имени администратора!", "Ошибка", MB_ICONERROR);
        return 1;
    }

    std::string dns1 = "176.99.11.77";
    std::string dns2 = "80.78.247.254";
    std::vector<std::string> interfaces = GetActiveInterfaces();

    if (interfaces.empty()) {
        MessageBoxA(NULL, "Не найдено активных сетевых интерфейсов!", "Ошибка", MB_ICONERROR);
        return 1;
    }

    int choice;
    std::cout << "==============================\n";
    std::cout << "    DNS IPv4 Переключатель    \n";
    std::cout << "==============================\n";
    std::cout << "[1] Включить DNS (статический)\n";
    std::cout << "[2] Выключить DNS (авто/DHCP)\n";
    std::cout << "Выберите действие: ";
    std::cin >> choice;

    switch (choice) {
    case 1:
        EnableDNS(interfaces, dns1, dns2);
        MessageBoxA(NULL, "DNS включен!", "Готово", MB_ICONINFORMATION);
        break;
    case 2:
        DisableDNS(interfaces);
        MessageBoxA(NULL, "DNS сброшен на авто!", "Готово", MB_ICONINFORMATION);
        break;
    default:
        std::cout << "Неверный выбор.\n";
        break;
    }

    return 0;
}
