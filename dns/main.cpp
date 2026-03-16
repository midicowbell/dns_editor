#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

struct DnsPreset {
    std::string name;
    std::string primary;
    std::string secondary;
};

void SetColor(int color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

bool IsRunningAsAdmin() {
    BOOL isMember = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    if (AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &AdministratorsGroup))
    {
        CheckTokenMembership(NULL, AdministratorsGroup, &isMember);
        FreeSid(AdministratorsGroup);
    }
    return isMember;
}

void RunCommandHidden(const std::string& cmd) {
    SHELLEXECUTEINFOA sei = { 0 };
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = "open";
    sei.lpFile = "cmd.exe";
    std::string params = "/c " + cmd;
    sei.lpParameters = params.c_str();
    sei.nShow = SW_HIDE;

    if (ShellExecuteExA(&sei)) {
        WaitForSingleObject(sei.hProcess, INFINITE);
        CloseHandle(sei.hProcess);
    }
}

void FlushDNS() {
    SetColor(8);
    std::cout << "\n[INFO] Flushing DNS cache...\n";
    RunCommandHidden("ipconfig /flushdns");
    SetColor(10);
    std::cout << "[OK] DNS cache cleared.\n";
    SetColor(7);
}

std::vector<std::string> GetActiveInterfaces() {
    std::vector<std::string> result;
    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses =
        (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);

    if (!pAddresses)
        return result;

    if (GetAdaptersAddresses(AF_INET, 0, NULL, pAddresses, &outBufLen) == NO_ERROR) {
        for (auto p = pAddresses; p; p = p->Next) {
            if (p->OperStatus == IfOperStatusUp) {
                std::wstring ws(p->FriendlyName);
                result.emplace_back(ws.begin(), ws.end());
            }
        }
    }

    free(pAddresses);
    return result;
}

void DrawHeader() {
    SetColor(10);
    std::cout <<
        "========================================\n"
        "           PREMIUM DNS SWITCHER         \n"
        "========================================\n";
    SetColor(7);
}

void DrawSection(const std::string& title) {
    SetColor(11);
    std::cout << "\n--- " << title << " ---\n";
    SetColor(7);
}

void ShowCurrentStatus() {
    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses =
        (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);

    if (!pAddresses)
        return;

    DrawSection("Current Network Status");

    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST, NULL, pAddresses, &outBufLen) == NO_ERROR) {
        bool any = false;
        for (auto p = pAddresses; p; p = p->Next) {
            if (p->OperStatus == IfOperStatusUp) {
                any = true;
                std::wstring ws(p->FriendlyName);
                std::string name(ws.begin(), ws.end());

                std::cout << "Interface: " << name << "\nDNS: ";

                auto dns = p->FirstDnsServerAddress;
                if (dns) {
                    while (dns) {
                        char buf[64] = {};
                        if (getnameinfo(
                            dns->Address.lpSockaddr,
                            dns->Address.iSockaddrLength,
                            buf, sizeof(buf),
                            NULL, 0,
                            NI_NUMERICHOST) == 0)
                        {
                            std::cout << buf << " ";
                        }
                        dns = dns->Next;
                    }
                }
                else {
                    std::cout << "DHCP (Auto)";
                }

                std::cout << "\n\n";
            }
        }
        if (!any) {
            std::cout << "No active interfaces found.\n";
        }
    }
    else {
        std::cout << "Failed to query adapters.\n";
    }

    free(pAddresses);
}

void ShowMenu(const std::vector<DnsPreset>& presets) {
    DrawSection("DNS Providers");

    for (int i = 0; i < (int)presets.size(); ++i) {
        std::cout << " [" << i + 1 << "] "
            << presets[i].name
            << " (" << presets[i].primary << ")\n";
    }

    std::cout <<
        "\n [5] Reset to DHCP\n"
        " [0] Exit\n\n"
        "Choose option: ";
}

int main() {
    // Включаем UTF-8 в консоли
    SetConsoleOutputCP(CP_UTF8);
    system("chcp 65001 > nul");

    if (!IsRunningAsAdmin()) {
        MessageBoxA(NULL,
            "Please run this program as Administrator!",
            "Error",
            MB_OK | MB_ICONERROR);
        return 1;
    }

    std::vector<DnsPreset> presets = {
        {"Xbox DNS", "87.228.47.200", "87.228.47.201"},
        {"Google DNS", "8.8.8.8", "8.8.4.4"},
        {"Cloudflare", "1.1.1.1", "1.0.0.1"},
        {"AdGuard (Ads Block)", "94.140.14.14", "94.140.15.15"}
    };

    while (true) {
        system("cls");
        DrawHeader();
        ShowCurrentStatus();
        ShowMenu(presets);

        int choice = -1;
        std::cin >> choice;

        if (!std::cin) {
            std::cin.clear();
            std::cin.ignore(1024, '\n');
            continue;
        }

        if (choice == 0)
            break;

        auto interfaces = GetActiveInterfaces();
        if (interfaces.empty()) {
            std::cout << "\n[WARN] No active interfaces. Press Enter...";
            std::cin.ignore();
            std::cin.get();
            continue;
        }

        if (choice >= 1 && choice <= 4) {
            DnsPreset dns = presets[choice - 1];

            DrawSection("Applying DNS");
            for (const auto& iface : interfaces) {
                std::string cmd =
                    "netsh interface ipv4 set dns name=\"" + iface + "\" static " + dns.primary + " primary && "
                    "netsh interface ipv4 add dns name=\"" + iface + "\" " + dns.secondary + " index=2";

                std::cout << "[...] " << iface << " -> " << dns.name << "\n";
                RunCommandHidden(cmd);
                std::cout << "[OK] Applied to " << iface << "\n";
            }

            FlushDNS();
            MessageBoxA(NULL,
                "DNS updated and cache cleared!",
                "Success",
                MB_OK);
        }
        else if (choice == 5) {
            DrawSection("Resetting to DHCP");
            for (const auto& iface : interfaces) {
                std::cout << "[...] " << iface << " -> DHCP\n";
                RunCommandHidden("netsh interface ipv4 set dns name=\"" + iface + "\" dhcp");
                std::cout << "[OK] " << iface << " now uses DHCP\n";
            }
            FlushDNS();
            MessageBoxA(NULL,
                "DNS reset to DHCP!",
                "Success",
                MB_OK);
        }

        std::cout << "\nPress Enter to continue...";
        std::cin.ignore();
        std::cin.get();
    }

    return 0;
}
