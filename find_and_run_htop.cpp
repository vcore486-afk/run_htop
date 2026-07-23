#include <iostream>
#include <string>
#include <vector>
#include <future>
#include <chrono>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")

const std::string USER = "definitly";
const std::string PASS = "639639";
const int START_IP = 100;
const int END_IP = 110;
const std::string SUBNET = "192.168.8.";

// Структура для передачи данных в EnumWindows Callback
struct FindWindowData {
    DWORD processId;
    HWND hWnd;
};

// Функция проверки одного IP-адреса на наличие баннера FreeBSD
std::string check_ip(const std::string& ip) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return "";

    // Устанавливаем сокет в неблокирующий режим для таймаута
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    sockaddr_in clientService;
    clientService.sin_family = AF_INET;
    clientService.sin_port = htons(22);
    inet_pton(AF_INET, ip.c_str(), &clientService.sin_addr);

    connect(sock, (SOCKADDR*)&clientService, sizeof(clientService));

    // Таймаут подключения: 150 мс
    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(sock, &writeSet);
    timeval timeout{ 0, 150000 }; 

    if (select(0, nullptr, &writeSet, nullptr, &timeout) > 0) {
        // Возвращаем в блокирующий режим для чтения баннера
        mode = 0;
        ioctlsocket(sock, FIONBIO, &mode);

        // Таймаут на чтение: 200 мс
        DWORD readTimeout = 200;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&readTimeout, sizeof(readTimeout));

        char buffer[256] = { 0 };
        int bytesReceived = recv(sock, buffer, sizeof(buffer) - 1, 0);

        if (bytesReceived > 0) {
            std::string banner(buffer, bytesReceived);
            if (banner.find("FreeBSD") != std::string::npos) {
                closesocket(sock);
                return ip;
            }
        }
    }

    closesocket(sock);
    return "";
}

int main() {
    // Инициализация Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        MessageBoxA(NULL, "Не удалось инициализировать Winsock", "Ошибка", MB_OK | MB_ICONERROR);
        return 1;
    }

    std::vector<std::future<std::string>> futures;
    
    // Запускаем асинхронное сканирование диапазона
    for (int i = START_IP; i <= END_IP; ++i) {
        std::string ip = SUBNET + std::to_string(i);
        futures.push_back(std::async(std::launch::async, check_ip, ip));
    }

    std::string target_ip = "";
    for (auto& f : futures) {
        std::string res = f.get();
        if (!res.empty()) {
            target_ip = res;
            break; // Хост найден
        }
    }

    WSACleanup();

    if (target_ip.empty()) {
        MessageBoxA(NULL, "Хост FreeBSD не найден в сети 192.168.8.100-110", "Ошибка", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Формируем команду для запуска SSH
    std::string command = "cmd.exe /c ssh -t " + USER + "@" + target_ip + " \"htop\"";

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    // Запускаем процесс CMD с SSH (используем const_cast для соответствия сигнатуре API)
    if (CreateProcessA(NULL, const_cast<char*>(command.c_str()), NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        // Ждем, пока процесс создаст свое графическое окно консоли
        Sleep(500);

        FindWindowData data = { pi.dwProcessId, nullptr };

        // Ищем окно верхнего уровня, принадлежащее запущенному PID
        EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
            auto pData = reinterpret_cast<FindWindowData*>(lParam);
            DWORD pid = 0;
            GetWindowThreadProcessId(hwnd, &pid);
            if (pid == pData->processId && GetWindow(hwnd, GW_OWNER) == nullptr && IsWindowVisible(hwnd)) {
                pData->hWnd = hwnd;
                return FALSE; // Окно найдено, прекращаем перебор
            }
            return TRUE;
        }, reinterpret_cast<LPARAM>(&data));

        // Если окно успешно найдено, выводим его на передний план
        if (data.hWnd != nullptr) {
            SetForegroundWindow(data.hWnd);
            SetActiveWindow(data.hWnd);
        }

        // Запас времени, чтобы SSH успел вывести запрос пароля
        Sleep(500);

        // Имитируем ввод пароля посимвольно через WinAPI
        for (char c : PASS) {
            INPUT input = { 0 };
            input.type = INPUT_KEYBOARD;
            input.ki.wVk = 0;
            input.ki.wScan = static_cast<WORD>(c);
            input.ki.dwFlags = KEYEVENTF_UNICODE;
            SendInput(1, &input, sizeof(INPUT));
            
            input.ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
            SendInput(1, &input, sizeof(INPUT));
        }

        // Имитируем нажатие Enter (Ввод)
        INPUT inputEnter = { 0 };
        inputEnter.type = INPUT_KEYBOARD;
        inputEnter.ki.wVk = VK_RETURN;
        SendInput(1, &inputEnter, sizeof(INPUT));
        
        inputEnter.ki.dwFlags = KEYEVENTF_KEYUP;
        SendInput(1, &inputEnter, sizeof(INPUT));

        // Закрываем дескрипторы процесса
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        MessageBoxA(NULL, "Не удалось запустить SSH процесс", "Ошибка", MB_OK | MB_ICONERROR);
    }

    return 0;
}
