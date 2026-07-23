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
//     4. На сессию libssh2 выставлен таймаут (libssh2_session_set_timeout),
//        иначе зависшая сеть/sshd вешает программу навсегда.
//     5. Установлен обработчик Ctrl+C/закрытия консоли (SetConsoleCtrlHandler),
//        который аварийно закрывает канал и сессию, чтобы htop и SSH-сессия
//        не оставались висеть на сервере при неаккуратном завершении клиента.
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

#include <atomic>
#include <csignal>
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
constexpr long        SESSION_TIMEOUT_MS = 15000;

constexpr const char* SSH_USER = "definitly";
constexpr const char* SSH_PASS = "639639";

// Команда, которую запускаем в PTY вместо REMOTE_COMMANDS из оригинала.
constexpr const char* REMOTE_COMMAND = "htop\n";

const char* g_kbdPassword = SSH_PASS;

// --- Аварийная очистка при Ctrl+C / закрытии консоли ---------------------
//
// ConsoleCtrlHandler вызывается Windows в ОТДЕЛЬНОМ потоке, параллельно с
// основным потоком, который в этот момент может быть заблокирован внутри
// libssh2 (аутентификация, чтение/запись канала и т.п.). Вызов функций
// libssh2 из двух потоков одновременно на одной сессии в общем случае
// небезопасен, но здесь это осознанный компромисс: лучше рискнуть гонкой
// данных ради шанса закрыть канал, чем гарантированно оставить htop висеть
// на сервере. Флаг g_shuttingDown гарантирует, что очистка выполнится не
// больше одного раза.
std::atomic<LIBSSH2_CHANNEL*> g_activeChannel{nullptr};
std::atomic<LIBSSH2_SESSION*> g_activeSession{nullptr};
std::atomic<SOCKET>           g_activeSocket{INVALID_SOCKET};
std::atomic<bool>             g_shuttingDown{false};

BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
    if (ctrlType != CTRL_C_EVENT && ctrlType != CTRL_BREAK_EVENT &&
        ctrlType != CTRL_CLOSE_EVENT && ctrlType != CTRL_LOGOFF_EVENT &&
        ctrlType != CTRL_SHUTDOWN_EVENT) {
        return FALSE;
    }

    if (g_shuttingDown.exchange(true)) {
        return TRUE; // уже закрываемся, повторный сигнал игнорируем
    }

    std::cerr << "\nПолучен сигнал завершения, закрываю SSH-канал...\n";

    LIBSSH2_CHANNEL* channel = g_activeChannel.load();
    if (channel) {
        libssh2_channel_send_eof(channel);
        libssh2_channel_close(channel);
        libssh2_channel_free(channel);
        g_activeChannel = nullptr;
    }

    LIBSSH2_SESSION* session = g_activeSession.load();
    if (session) {
        libssh2_session_disconnect(session, "Client interrupted");
        libssh2_session_free(session);
        g_activeSession = nullptr;
    }

    SOCKET sock = g_activeSocket.load();
    if (sock != INVALID_SOCKET) {
        closesocket(sock);
        g_activeSocket = INVALID_SOCKET;
    }

    // CTRL_CLOSE_EVENT/LOGOFF/SHUTDOWN дают ограниченное время на завершение
    // (обычно ~5 сек), поэтому выходим сразу, не дожидаясь возврата из main().
    if (ctrlType == CTRL_CLOSE_EVENT || ctrlType == CTRL_LOGOFF_EVENT ||
        ctrlType == CTRL_SHUTDOWN_EVENT) {
        ExitProcess(1);
    }

    return TRUE;
}

void KeyboardInteractiveCallback(const char* /*name*/, int /*name_len*/,
                                  const char* /*instruction*/, int /*instruction_len*/,
                                  int num_prompts,
                                  const LIBSSH2_USERAUTH_KBDINT_PROMPT* /*prompts*/,
                                  LIBSSH2_USERAUTH_KBDINT_RESPONSE* responses,
                                  void** /*abstract*/) {
    for (int i = 0; i < num_prompts; ++i) {
        responses[i].text = _strdup(g_kbdPassword);
        responses[i].length = static_cast<unsigned int>(strlen(g_kbdPassword));
    }
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
// Возвращается, когда пользователь выходит из htop (канал закрывается / EOF)
// либо когда истёк таймаут сессии (LIBSSH2_ERROR_TIMEOUT).
void InteractivePump(LIBSSH2_CHANNEL* channel) {
    libssh2_channel_set_blocking(channel, 0);

    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    char inBuf[256];
    char outBuf[4096];

    while (!g_shuttingDown.load()) {
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
                    if (n == LIBSSH2_ERROR_TIMEOUT) {
                        std::cerr << "\nТаймаут при записи в канал, завершаю сессию\n";
                        return;
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
        } else if (n == LIBSSH2_ERROR_TIMEOUT) {
            std::cerr << "\nТаймаут при чтении канала, завершаю сессию\n";
            break;
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

    LIBSSH2_SESSION* session = libssh2_session_init();
    if (!session) {
        std::cerr << "libssh2_session_init() не удалось\n";
        closesocket(sock);
        return false;
    }

    if (libssh2_session_handshake(session, sock) != 0) {
        std::cerr << "SSH handshake не удался\n";
        libssh2_session_free(session);
        closesocket(sock);
        return false;
    }

    // Таймаут на все последующие блокирующие вызовы libssh2 (аутентификация,
    // exec, чтение/запись канала) - без него зависшая сеть/sshd вешает
    // программу навсегда, как это было при повторном запуске.
    libssh2_session_set_timeout(session, SESSION_TIMEOUT_MS);

    g_activeSession = session;
    g_activeSocket  = sock;

    if (!AuthenticateSession(session)) {
        char* errMsg = nullptr;
        libssh2_session_last_error(session, &errMsg, nullptr, 0);
        std::cerr << "Аутентификация не удалась: " << (errMsg ? errMsg : "неизвестная ошибка") << "\n";
        libssh2_session_disconnect(session, "Auth failed");
        libssh2_session_free(session);
        g_activeSession = nullptr;
        closesocket(sock);
        g_activeSocket = INVALID_SOCKET;
        return false;
    }

    LIBSSH2_CHANNEL* channel = libssh2_channel_open_session(session);
    if (!channel) {
        std::cerr << "Не удалось открыть канал\n";
        libssh2_session_disconnect(session, "Channel error");
        libssh2_session_free(session);
        g_activeSession = nullptr;
        closesocket(sock);
        g_activeSocket = INVALID_SOCKET;
        return false;
    }

    g_activeChannel = channel;

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
        g_activeChannel = nullptr;
        libssh2_session_disconnect(session, "PTY error");
        libssh2_session_free(session);
        g_activeSession = nullptr;
        closesocket(sock);
        g_activeSocket = INVALID_SOCKET;
        return false;
    }

    if (libssh2_channel_exec(channel, REMOTE_COMMAND) != 0) {
        std::cerr << "Не удалось запустить htop\n";
        libssh2_channel_free(channel);
        g_activeChannel = nullptr;
        libssh2_session_disconnect(session, "Exec error");
        libssh2_session_free(session);
        g_activeSession = nullptr;
        closesocket(sock);
        g_activeSocket = INVALID_SOCKET;
        return false;
    }

    {
        ConsoleRawGuard rawGuard; // включаем "сырой" режим консоли на время сессии htop
        InteractivePump(channel);
    } // деструктор восстанавливает исходный режим консоли

    // Если ConsoleCtrlHandler успел выполнить аварийную очистку параллельно
    // (g_shuttingDown уже true), объекты уже закрыты и обнулены - повторно их
    // трогать нельзя.
    if (!g_shuttingDown.load()) {
        libssh2_channel_close(channel);
        int exitCode = libssh2_channel_get_exit_status(channel);
        libssh2_channel_free(channel);
        g_activeChannel = nullptr;

        libssh2_session_disconnect(session, "Done");
        libssh2_session_free(session);
        g_activeSession = nullptr;

        closesocket(sock);
        g_activeSocket = INVALID_SOCKET;

        std::cout << "\nhtop завершён, код выхода: " << exitCode << "\n";
    }

    return true;
}

} // namespace

int main() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    if (!SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE)) {
        std::cerr << "Не удалось установить обработчик Ctrl+C (не критично)\n";
    }

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