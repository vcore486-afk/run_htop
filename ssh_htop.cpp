// ssh_htop.cpp
//
// Аналог switch_winvm_off.cpp, но вместо разовой команды запускает
// интерактивный htop на удалённом FreeBSD-хосте.
//
// Отличия от "выполнить команду и прочитать вывод":
//   htop - полноэкранное ncurses-приложение, поэтому:
//     1. Каналу нужен PTY (libssh2_channel_request_pty), иначе htop
//        откажется рисовать интерфейс (не терминал).
//     2. Нужен интерактивный проброс: то, что пользователь печатает
//        в консоли (F6, q, стрелки...), должно уходить в канал,
//        а то, что канал присылает (ANSI-escape-рисование htop),
//        должно сразу лететь в stdout консоли.
//     3. Локальная консоль переводится в "сырой" режим (без построчного
//        буфера и локального эха), иначе ввод будет буферизоваться до Enter.
//
// Сборка (MSVC, x64 Native Tools Command Prompt):
//   cl /EHsc /std:c++17 ssh_htop.cpp Ws2_32.lib libssh2.lib /I <путь_к_include_libssh2>
//
// Сборка (MinGW):
//   g++ -std=c++17 ssh_htop.cpp -lssh2 -lws2_32 -o ssh_htop.exe

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <libssh2.h>

#include <iostream>
#include <string>
#include <cstring>

#pragma comment(lib, "Ws2_32.lib")

namespace {

constexpr const char* SUBNET_PREFIX   = "192.168.8.";
constexpr int         SCAN_FIRST      = 100;
constexpr int         SCAN_LAST       = 110;
constexpr int         SSH_PORT        = 22;
constexpr int         CONNECT_TIMEOUT_MS = 150;
constexpr int         BANNER_TIMEOUT_MS  = 200;

constexpr const char* SSH_USER = "definitly";
constexpr const char* SSH_PASS = "639639";

// Команда, которую запускаем в PTY вместо REMOTE_COMMANDS из оригинала.
constexpr const char* REMOTE_COMMAND = "htop\n";

const char* g_kbdPassword = SSH_PASS;

void KeyboardInteractiveCallback(const char* name, int name_len,
                                  const char* instruction, int instruction_len,
                                  int num_prompts,
                                  const LIBSSH2_USERAUTH_KBDINT_PROMPT* prompts,
                                  LIBSSH2_USERAUTH_KBDINT_RESPONSE* responses,
                                  void** /*abstract*/) {
    // ВРЕМЕННАЯ ДИАГНОСТИКА: если этот блок вообще не печатается -
    // значит зависание происходит ДО получения INFO_REQUEST от сервера
    // (т.е. проблема на уровне сокета/сети/сервера, а не в нашем коде).
    std::cerr << "[kbd-interactive] name=\"" << std::string(name, name_len)
              << "\" instruction=\"" << std::string(instruction, instruction_len)
              << "\" num_prompts=" << num_prompts << "\n";
    for (int i = 0; i < num_prompts; ++i) {
        std::cerr << "[kbd-interactive] prompt[" << i << "]=\""
                  << std::string(reinterpret_cast<const char*>(prompts[i].text), prompts[i].length)
                  << "\" echo=" << static_cast<int>(prompts[i].echo) << "\n";
        responses[i].text = _strdup(g_kbdPassword);
        responses[i].length = static_cast<unsigned int>(strlen(g_kbdPassword));
    }
    std::cerr << "[kbd-interactive] ответ отправлен\n";
}

// Тот же порядок: сначала "password", если сервер его не предлагает -
// "keyboard-interactive" (частый случай при PasswordAuthentication no +
// KbdInteractiveAuthentication yes в sshd_config).
bool AuthenticateSession(LIBSSH2_SESSION* session) {
    char* userAuthList = libssh2_userauth_list(session, SSH_USER,
                                                static_cast<unsigned int>(strlen(SSH_USER)));
    std::string methods = userAuthList ? userAuthList : "";
    std::cout << "Сервер предлагает методы аутентификации: " << methods << "\n";

    if (methods.find("password") != std::string::npos) {
        if (libssh2_userauth_password(session, SSH_USER, SSH_PASS) == 0) {
            return true;
        }
        std::cerr << "Метод password не сработал, пробуем keyboard-interactive...\n";
    }

    if (methods.find("keyboard-interactive") != std::string::npos) {
        if (libssh2_userauth_keyboard_interactive(session, SSH_USER,
                                                   &KeyboardInteractiveCallback) == 0) {
            return true;
        }
    }

    return false;
}

bool ConnectWithTimeout(SOCKET sock, const sockaddr_in& addr, int timeoutMs) {
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    int res = connect(sock, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
    if (res == 0) {
        mode = 0;
        ioctlsocket(sock, FIONBIO, &mode);
        return true;
    }

    if (WSAGetLastError() != WSAEWOULDBLOCK) {
        return false;
    }

    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(sock, &writeSet);

    timeval tv{};
    tv.tv_sec  = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;

    int sel = select(0, nullptr, &writeSet, nullptr, &tv);
    if (sel <= 0) {
        return false;
    }

    int err = 0;
    int errLen = sizeof(err);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &errLen);

    mode = 0;
    ioctlsocket(sock, FIONBIO, &mode);

    return err == 0;
}

bool ReadBannerWithTimeout(SOCKET sock, std::string& outBanner, int timeoutMs) {
    fd_set readSet;
    FD_ZERO(&readSet);
    FD_SET(sock, &readSet);

    timeval tv{};
    tv.tv_sec  = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;

    int sel = select(0, &readSet, nullptr, nullptr, &tv);
    if (sel <= 0) {
        return false;
    }

    char buf[256] = {};
    int n = recv(sock, buf, sizeof(buf) - 1, 0);
    if (n <= 0) {
        return false;
    }

    outBanner.assign(buf, n);
    return true;
}

std::string FindFreeBsdHost() {
    for (int last = SCAN_FIRST; last <= SCAN_LAST; ++last) {
        std::string ip = std::string(SUBNET_PREFIX) + std::to_string(last);

        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            continue;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(SSH_PORT);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

        if (ConnectWithTimeout(sock, addr, CONNECT_TIMEOUT_MS)) {
            std::string banner;
            if (ReadBannerWithTimeout(sock, banner, BANNER_TIMEOUT_MS) &&
                banner.find("FreeBSD") != std::string::npos) {
                closesocket(sock);
                std::cout << "Найден хост: " << ip << " (" << banner << ")\n";
                return ip;
            }
        }

        closesocket(sock);
    }
    return "";
}

// Переводит локальную консоль в "сырой" режим: без построчного буфера,
// без локального эха, с поддержкой ANSI-escape (нужно htop для отрисовки).
// Возвращает исходные режимы stdin/stdout, чтобы восстановить их на выходе.
struct ConsoleRawGuard {
    HANDLE hIn  = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD  oldInMode  = 0;
    DWORD  oldOutMode = 0;

    ConsoleRawGuard() {
        GetConsoleMode(hIn, &oldInMode);
        GetConsoleMode(hOut, &oldOutMode);

        DWORD newIn = oldInMode;
        newIn &= ~static_cast<DWORD>(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
        newIn |= ENABLE_VIRTUAL_TERMINAL_INPUT;
        SetConsoleMode(hIn, newIn);

        DWORD newOut = oldOutMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, newOut);
    }

    ~ConsoleRawGuard() {
        SetConsoleMode(hIn, oldInMode);
        SetConsoleMode(hOut, oldOutMode);
    }
};

// Интерактивный проброс: читает нажатия клавиш из консоли и шлёт их в канал,
// читает то, что канал присылает (рисование htop), и сразу пишет в stdout.
// Возвращается, когда пользователь выходит из htop (канал закрывается / EOF).
void InteractivePump(LIBSSH2_CHANNEL* channel) {
    libssh2_channel_set_blocking(channel, 0);

    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    char inBuf[256];
    char outBuf[4096];

    while (true) {
        bool didWork = false;

        // 1) Ввод пользователя -> канал
        DWORD events = 0;
        if (GetNumberOfConsoleInputEvents(hIn, &events) && events > 0) {
            DWORD read = 0;
            if (ReadFile(hIn, inBuf, sizeof(inBuf), &read, nullptr) && read > 0) {
                ssize_t off = 0;
                while (off < static_cast<ssize_t>(read)) {
                    ssize_t n = libssh2_channel_write(channel, inBuf + off,
                                                       static_cast<size_t>(read - off));
                    if (n == LIBSSH2_ERROR_EAGAIN) {
                        continue;
                    }
                    if (n < 0) {
                        return; // канал закрыт/ошибка
                    }
                    off += n;
                }
                didWork = true;
            }
        }

        // 2) Вывод htop из канала -> stdout
        ssize_t n = libssh2_channel_read(channel, outBuf, sizeof(outBuf));
        if (n > 0) {
            DWORD written = 0;
            WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), outBuf,
                      static_cast<DWORD>(n), &written, nullptr);
            didWork = true;
        } else if (n == 0) {
            break; // EOF: htop завершился
        } else if (n != LIBSSH2_ERROR_EAGAIN) {
            break; // реальная ошибка чтения
        }

        if (libssh2_channel_eof(channel)) {
            break;
        }

        if (!didWork) {
            Sleep(10); // не жечь CPU в холостом цикле
        }
    }
}

bool RunRemoteHtop(const std::string& ip) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Не удалось создать сокет для SSH-подключения\n";
        return false;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(SSH_PORT);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    if (connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        std::cerr << "Не удалось подключиться к " << ip << ":22\n";
        closesocket(sock);
        return false;
    }

    // Таймаут на recv/send, чтобы при проблеме на уровне протокола/сети
    // получить понятную ошибку вместо вечного зависания.
    DWORD sockTimeoutMs = 15000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&sockTimeoutMs), sizeof(sockTimeoutMs));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
               reinterpret_cast<const char*>(&sockTimeoutMs), sizeof(sockTimeoutMs));

    LIBSSH2_SESSION* session = libssh2_session_init();
    if (!session) {
        std::cerr << "libssh2_session_init() не удалось\n";
        closesocket(sock);
        return false;
    }

    // ВРЕМЕННАЯ ДИАГНОСТИКА: подробный лог протокольного обмена в stderr.
    // Требует, чтобы libssh2 был собран с поддержкой трейсинга (обычно да по умолчанию).
    libssh2_trace(session, LIBSSH2_TRACE_TRANS | LIBSSH2_TRACE_AUTH | LIBSSH2_TRACE_SOCKET);

    // Таймаут именно на уровне libssh2 (в миллисекундах): блокирующие вызовы
    // (handshake, userauth, чтение/запись канала) вернут LIBSSH2_ERROR_TIMEOUT,
    // если за это время не получат нужные данные. В отличие от SO_RCVTIMEO на
    // сокете, это учитывает внутренний retry-on-EAGAIN цикл самого libssh2.
    libssh2_session_set_timeout(session, 20000);

    if (libssh2_session_handshake(session, sock) != 0) {
        std::cerr << "SSH handshake не удался\n";
        libssh2_session_free(session);
        closesocket(sock);
        return false;
    }

    if (!AuthenticateSession(session)) {
        char* errMsg = nullptr;
        libssh2_session_last_error(session, &errMsg, nullptr, 0);
        std::cerr << "Аутентификация не удалась: " << (errMsg ? errMsg : "неизвестная ошибка") << "\n";
        libssh2_session_disconnect(session, "Auth failed");
        libssh2_session_free(session);
        closesocket(sock);
        return false;
    }

    LIBSSH2_CHANNEL* channel = libssh2_channel_open_session(session);
    if (!channel) {
        std::cerr << "Не удалось открыть канал\n";
        libssh2_session_disconnect(session, "Channel error");
        libssh2_session_free(session);
        closesocket(sock);
        return false;
    }

    // Ключевое отличие от exec-варианта: htop без PTY откажется рисовать интерфейс.
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    int cols = 80, rows = 24;
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi)) {
        cols = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        rows = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
    }

    if (libssh2_channel_request_pty_ex(channel, "xterm", 5, nullptr, 0,
                                        cols, rows, 0, 0) != 0) {
        std::cerr << "Не удалось запросить PTY\n";
        libssh2_channel_free(channel);
        libssh2_session_disconnect(session, "PTY error");
        libssh2_session_free(session);
        closesocket(sock);
        return false;
    }

    if (libssh2_channel_exec(channel, REMOTE_COMMAND) != 0) {
        std::cerr << "Не удалось запустить htop\n";
        libssh2_channel_free(channel);
        libssh2_session_disconnect(session, "Exec error");
        libssh2_session_free(session);
        closesocket(sock);
        return false;
    }

    {
        ConsoleRawGuard rawGuard; // включаем "сырой" режим консоли на время сессии htop
        InteractivePump(channel);
    } // деструктор восстанавливает исходный режим консоли

    libssh2_channel_close(channel);
    int exitCode = libssh2_channel_get_exit_status(channel);
    libssh2_channel_free(channel);

    libssh2_session_disconnect(session, "Done");
    libssh2_session_free(session);
    closesocket(sock);

    std::cout << "\nhtop завершён, код выхода: " << exitCode << "\n";
    return true;
}

} // namespace

int main() {
    std::cerr << "=== BUILD MARKER: ssh_htop v2 (timeout+trace) ===\n";

    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup не удался\n";
        return 1;
    }

    if (libssh2_init(0) != 0) {
        std::cerr << "libssh2_init() не удался\n";
        WSACleanup();
        return 1;
    }

    std::cerr << "libssh2 version: " << libssh2_version(0) << "\n";

    std::string ip = FindFreeBsdHost();
    if (ip.empty()) {
        std::cerr << "FreeBSD-хост в диапазоне "
                  << SUBNET_PREFIX << SCAN_FIRST << "-" << SCAN_LAST << " не найден\n";
        libssh2_exit();
        WSACleanup();
        return 1;
    }

    bool ok = RunRemoteHtop(ip);

    libssh2_exit();
    WSACleanup();

    return ok ? 0 : 1;
}
