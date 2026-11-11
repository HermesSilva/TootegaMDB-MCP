#if !defined(_WIN32)
#  define _POSIX_C_SOURCE 200809L
#  define _DEFAULT_SOURCE
#endif

#include "plat.h"
#include "crypto/curve.h"
#include "crypto/hash.h"
#include "crypto/x509.h"
#include "i18n.h"
#include "tls.h"

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#  include <bcrypt.h>
#  include <wincrypt.h>
#  include <fcntl.h>
#  include <io.h>
#  include <sys/stat.h>
typedef SOCKET sock_t;
#  define SOCK_BAD   INVALID_SOCKET
#  define sock_close closesocket
#  define sock_errno WSAGetLastError()
#  define E_WOULD    WSAEWOULDBLOCK
#  define E_INPROG   WSAEWOULDBLOCK
#  define E_INTR     WSAEINTR
#else
#  include <errno.h>
#  include <fcntl.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <poll.h>
#  include <signal.h>
#  include <sys/socket.h>
#  include <sys/stat.h>
#  include <time.h>
#  include <unistd.h>
typedef int sock_t;
#  define SOCK_BAD   (-1)
#  define sock_close close
#  define sock_errno errno
#  define E_WOULD    EAGAIN
#  define E_INPROG   EINPROGRESS
#  define E_INTR     EINTR
#endif

/* ---- geral ---- */

int plat_init(void)
{
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return -1;
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
    _setmode(_fileno(stderr), _O_BINARY);
#else
    signal(SIGPIPE, SIG_IGN);
#endif
    return 0;
}

int64_t plat_now_ms(void)
{
#ifdef _WIN32
    /* GetTickCount64 anda de ~16 em 16 ms; latência de conexão pede mais resolução. */
    static LARGE_INTEGER freq;
    LARGE_INTEGER now;
    if (!freq.QuadPart) QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&now);
    return (int64_t)(now.QuadPart / freq.QuadPart) * 1000 + (int64_t)(now.QuadPart % freq.QuadPart) * 1000 / freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

int plat_random(void *p, size_t n)
{
#ifdef _WIN32
    return BCryptGenRandom(NULL, (PUCHAR)p, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? 0 : -1;
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t got = fread(p, 1, n, f);
    fclose(f);
    return got == n ? 0 : -1;
#endif
}

#ifdef _WIN32
/* Caminhos e variáveis chegam em UTF-8; a API do Windows quer UTF-16. */
static wchar_t *to_wide(const char *s)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0) return NULL;
    wchar_t *w = tm_alloc((size_t)n * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}
#endif

const char *plat_getenv(const char *name)
{
#ifdef _WIN32
    /* getenv devolveria na página de código ANSI e estragaria acentos (ex.: C:\Users\José).
     * O valor convertido fica alocado; são poucas chamadas na vida do processo. */
    wchar_t *wname = to_wide(name);
    const wchar_t *wv = wname ? _wgetenv(wname) : NULL;
    free(wname);
    if (!wv || !*wv) return NULL;
    int n = WideCharToMultiByte(CP_UTF8, 0, wv, -1, NULL, 0, NULL, NULL);
    if (n <= 0) return NULL;
    char *v = tm_alloc((size_t)n);
    WideCharToMultiByte(CP_UTF8, 0, wv, -1, v, n, NULL, NULL);
    return v;
#else
    const char *v = getenv(name);
    return (v && *v) ? v : NULL;
#endif
}

const char *plat_lang(void)
{
#ifdef _WIN32
    return (GetUserDefaultUILanguage() & 0x3FF) == 0x16 ? "pt" : "en"; /* LANG_PORTUGUESE */
#else
    static const char *const vars[] = { "LC_ALL", "LC_MESSAGES", "LANG" };
    for (size_t i = 0; i < TM_COUNT(vars); i++) {
        const char *v = plat_getenv(vars[i]);
        if (v) return tm_strnicmp(v, "pt", 2) == 0 ? "pt" : "en";
    }
    return "en";
#endif
}

char *plat_default_config_path(void)
{
    tm_buf b;
    buf_init(&b);
#ifdef _WIN32
    const char *base = plat_getenv("APPDATA");
    if (!base) return NULL;
    buf_printf(&b, "%s\\TootegaMDB\\connections.json", base);
#else
    const char *xdg = plat_getenv("XDG_CONFIG_HOME");
    const char *home = plat_getenv("HOME");
    if (xdg) buf_printf(&b, "%s/tootega-mdb/connections.json", xdg);
    else if (home) buf_printf(&b, "%s/.config/tootega-mdb/connections.json", home);
    else return NULL;
#endif
    return buf_cstr(&b);
}

int64_t plat_file_mtime(const char *path)
{
#ifdef _WIN32
    wchar_t *w = to_wide(path);
    if (!w) return -1;
    struct _stat64 st;
    int rc = _wstat64(w, &st);
    free(w);
    return rc == 0 ? (int64_t)st.st_mtime * 1000 + (int64_t)(st.st_size % 1000) : -1;
#else
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (int64_t)st.st_mtim.tv_sec * 1000 + st.st_mtim.tv_nsec / 1000000;
#endif
}

int plat_read_file(const char *path, tm_buf *out, tm_err *err)
{
    FILE *f;
#ifdef _WIN32
    wchar_t *w = to_wide(path);
    f = w ? _wfopen(w, L"rb") : NULL;
    free(w);
#else
    f = fopen(path, "rb");
#endif
    if (!f) return tm_fail(err, TM_E_CONFIG, T(M_FILE_OPEN), path);
    char tmp[8192];
    size_t n;
    while ((n = fread(tmp, 1, sizeof tmp, f)) > 0) {
        buf_put(out, tmp, n);
        if (out->len > (64u << 20)) break; /* teto de sanidade */
    }
    fclose(f);
    return 0;
}

/* ---- segredos em repouso ---- */

#ifdef _WIN32
int plat_protect(const void *in, size_t n, tm_buf *out)
{
    DATA_BLOB src = { (DWORD)n, (BYTE *)(uintptr_t)in }, dst = { 0, NULL };
    if (!CryptProtectData(&src, L"Tootega Multi-Database MCP", NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &dst))
        return -1;
    buf_put(out, dst.pbData, dst.cbData);
    LocalFree(dst.pbData);
    return 0;
}

int plat_unprotect(const void *in, size_t n, tm_buf *out)
{
    DATA_BLOB src = { (DWORD)n, (BYTE *)(uintptr_t)in }, dst = { 0, NULL };
    if (!CryptUnprotectData(&src, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &dst)) return -1;
    buf_put(out, dst.pbData, dst.cbData);
    SecureZeroMemory(dst.pbData, dst.cbData);
    LocalFree(dst.pbData);
    return 0;
}

int plat_write_private(const char *path, const void *p, size_t n)
{
    tm_buf tmp;
    buf_init(&tmp);
    buf_printf(&tmp, "%s.tmp", path);
    wchar_t *wtmp = to_wide(buf_cstr(&tmp)), *wpath = to_wide(path);
    int rc = -1;
    FILE *f = wtmp ? _wfopen(wtmp, L"wb") : NULL;
    if (f) {
        bool ok = fwrite(p, 1, n, f) == n;
        ok = fclose(f) == 0 && ok;
        /* o perfil do usuário já restringe o acesso; a troca é atômica */
        if (ok && wpath && MoveFileExW(wtmp, wpath, MOVEFILE_REPLACE_EXISTING)) rc = 0;
    }
    free(wtmp);
    free(wpath);
    buf_free(&tmp);
    return rc;
}
#else
static void local_key(uint8_t key[32])
{
    tm_hash_ctx h;
    tm_buf id;
    tm_err ignore;
    unsigned long uid = (unsigned long)getuid();
    buf_init(&id);
    if (plat_read_file("/etc/machine-id", &id, &ignore)) plat_read_file("/var/lib/dbus/machine-id", &id, &ignore);
    hash_init(&TM_SHA256, &h);
    hash_update(&TM_SHA256, &h, "tootega-mdb-secrets-v1", 22);
    hash_update(&TM_SHA256, &h, id.p, id.len);
    hash_update(&TM_SHA256, &h, &uid, sizeof uid);
    hash_final(&TM_SHA256, &h, key);
    buf_free(&id);
}

int plat_protect(const void *in, size_t n, tm_buf *out)
{
    uint8_t key[32], nonce[12], tag[16];
    if (plat_random(nonce, sizeof nonce)) return -1;
    local_key(key);
    buf_put(out, nonce, sizeof nonce);
    buf_reserve(out, n);
    chapoly_seal(key, nonce, NULL, 0, in, n, out->p + out->len, tag);
    out->len += n;
    buf_put(out, tag, sizeof tag);
    tm_wipe(key, sizeof key);
    return 0;
}

int plat_unprotect(const void *in, size_t n, tm_buf *out)
{
    const uint8_t *p = in;
    uint8_t key[32];
    if (n < 28) return -1;
    local_key(key);
    size_t len = n - 28;
    buf_reserve(out, len);
    int rc = chapoly_open(key, p, NULL, 0, p + 12, len, p + 12 + len, out->p + out->len);
    if (rc == 0) out->len += len;
    tm_wipe(key, sizeof key);
    return rc;
}

int plat_write_private(const char *path, const void *p, size_t n)
{
    tm_buf tmp;
    buf_init(&tmp);
    buf_printf(&tmp, "%s.tmp", path);
    int rc = -1;
    int fd = open(buf_cstr(&tmp), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        bool ok = write(fd, p, n) == (ssize_t)n;
        ok = fchmod(fd, 0600) == 0 && ok;
        ok = close(fd) == 0 && ok;
        if (ok && rename(buf_cstr(&tmp), path) == 0) rc = 0;
    }
    buf_free(&tmp);
    return rc;
}
#endif

void plat_system_roots(struct x509_store *store)
{
#ifdef _WIN32
    /* Repositório "ROOT" do Windows: a mesma lista que o sistema usa. */
    HCERTSTORE h = CertOpenSystemStoreW(0, L"ROOT");
    if (!h) return;
    PCCERT_CONTEXT ctx = NULL;
    while ((ctx = CertEnumCertificatesInStore(h, ctx)) != NULL)
        if (ctx->dwCertEncodingType & X509_ASN_ENCODING)
            x509_store_add_der(store, ctx->pbCertEncoded, ctx->cbCertEncoded);
    CertCloseStore(h, 0);
#else
    /* Pacote de autoridades em PEM: o caminho varia por distribuição. */
    static const char *const paths[] = { "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
                                         "/etc/ssl/ca-bundle.pem", "/etc/ssl/cert.pem",
                                         "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem" };
    const char *custom = plat_getenv("SSL_CERT_FILE");
    for (size_t i = 0; i <= TM_COUNT(paths); i++) {
        const char *path = i == 0 ? custom : paths[i - 1];
        tm_buf text;
        tm_err ignore;
        if (!path || plat_file_mtime(path) < 0) continue;
        buf_init(&text);
        int added = plat_read_file(path, &text, &ignore) == 0
                        ? x509_store_add_pem(store, (const char *)text.p, text.len) : 0;
        buf_free(&text);
        if (added > 0) return;
    }
#endif
}

/* ---- sockets ---- */

static void set_nonblock(sock_t s)
{
#ifdef _WIN32
    u_long on = 1;
    ioctlsocket(s, FIONBIO, &on);
#else
    int fl = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, fl | O_NONBLOCK);
#endif
}

/* Espera o socket ficar pronto. 1 = pronto, 0 = prazo esgotado, -1 = erro. */
static int wait_sock(sock_t s, bool for_write, int64_t deadline)
{
    for (;;) {
        int ms = -1;
        if (deadline) {
            int64_t left = deadline - plat_now_ms();
            if (left <= 0) return 0;
            ms = left > 60000 ? 60000 : (int)left;
        }
#ifdef _WIN32
        fd_set set, ex;
        FD_ZERO(&set);
        FD_ZERO(&ex);
        FD_SET(s, &set);
        FD_SET(s, &ex);
        struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
        int rc = select(0, for_write ? NULL : &set, for_write ? &set : NULL, &ex, ms < 0 ? NULL : &tv);
        if (rc > 0) return 1;
        if (rc < 0) return -1;
#else
        struct pollfd pfd = { s, for_write ? POLLOUT : POLLIN, 0 };
        int rc = poll(&pfd, 1, ms);
        if (rc > 0) return 1;
        if (rc < 0 && errno != EINTR) return -1;
#endif
        /* rc == 0: fatia de espera terminou; o laço reavalia o prazo */
    }
}

static int io_fail(tm_io *io, tm_err *err, int code, const char *msg)
{
    io->broken = true;
    return tm_fail(err, code, "%s", msg);
}

int io_connect(tm_io *io, const char *host, int port, int timeout_ms, tm_err *err)
{
    memset(io, 0, offsetof(tm_io, rbuf));
    io->fd = (intptr_t)SOCK_BAD;
    io->broken = true;

    if (!host || !*host) return tm_fail(err, TM_E_CONFIG, "%s", T(M_HOST_REQUIRED));
    if (port <= 0 || port > 65535) return tm_fail(err, TM_E_CONFIG, T(M_BAD_PORT), port);

    char service[16];
    snprintf(service, sizeof service, "%d", port);
    struct addrinfo hints, *list = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, service, &hints, &list) != 0 || !list)
        return tm_fail(err, TM_E_IO, T(M_DNS_FAIL), host);

    int64_t deadline = timeout_ms > 0 ? plat_now_ms() + timeout_ms : 0;
    bool timed_out = false;
    sock_t s = SOCK_BAD;
    for (struct addrinfo *ai = list; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == SOCK_BAD) continue;
        set_nonblock(s);
        int rc = connect(s, ai->ai_addr, (int)ai->ai_addrlen);
        if (rc != 0 && (sock_errno == E_INPROG || sock_errno == E_WOULD)) {
            int w = wait_sock(s, true, deadline);
            if (w == 0) timed_out = true;
            if (w == 1) {
                int soerr = 0;
                socklen_t sl = sizeof soerr;
                getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &sl);
                rc = soerr == 0 ? 0 : -1;
            }
        }
        if (rc == 0) break;
        sock_close(s);
        s = SOCK_BAD;
    }
    freeaddrinfo(list);
    if (s == SOCK_BAD) {
        if (timed_out) return tm_fail(err, TM_E_TIMEOUT, T(M_CONNECT_TIMEOUT), host, port);
        return tm_fail(err, TM_E_IO, T(M_CONNECT_FAIL), host, port);
    }
    int one = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (const char *)&one, sizeof one);
    io->fd = (intptr_t)s;
    io->broken = false;
    return 0;
}

int plat_udp_query(const char *host, int port, const void *req, size_t reqlen, void *resp, size_t cap,
                   int timeout_ms)
{
    char service[16];
    struct addrinfo hints, *list = NULL;
    int got = -1;
    snprintf(service, sizeof service, "%d", port);
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, service, &hints, &list) != 0 || !list) return -1;
    int64_t deadline = plat_now_ms() + (timeout_ms > 0 ? timeout_ms : 2000);
    for (struct addrinfo *ai = list; ai && got < 0; ai = ai->ai_next) {
        sock_t s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == SOCK_BAD) continue;
        if (sendto(s, req, (int)reqlen, 0, ai->ai_addr, (int)ai->ai_addrlen) == (int)reqlen &&
            wait_sock(s, false, deadline) == 1)
            got = (int)recv(s, resp, (int)cap, 0);
        sock_close(s);
    }
    freeaddrinfo(list);
    return got;
}

void io_set_timeout(tm_io *io, int timeout_ms)
{
    io->deadline = timeout_ms > 0 ? plat_now_ms() + timeout_ms : 0;
}

int io_raw_send(tm_io *io, const void *p, size_t n, tm_err *err)
{
    sock_t s = (sock_t)io->fd;
    for (;;) {
        int chunk = n > (1u << 20) ? (1 << 20) : (int)n;
        int rc = (int)send(s, p, chunk, 0);
        if (rc >= 0) return rc;
        if (sock_errno == E_INTR) continue;
        if (sock_errno != E_WOULD) return io_fail(io, err, TM_E_IO, T(M_IO_SEND));
        int w = wait_sock(s, true, io->deadline);
        if (w == 0) return io_fail(io, err, TM_E_TIMEOUT, T(M_IO_TIMEOUT));
        if (w < 0) return io_fail(io, err, TM_E_IO, T(M_IO_SEND));
    }
}

int io_raw_recv(tm_io *io, void *p, size_t n, tm_err *err)
{
    sock_t s = (sock_t)io->fd;
    for (;;) {
        int rc = (int)recv(s, p, (int)n, 0);
        if (rc > 0) return rc;
        if (rc == 0) return io_fail(io, err, TM_E_IO, T(M_IO_CLOSED));
        if (sock_errno == E_INTR) continue;
        if (sock_errno != E_WOULD) return io_fail(io, err, TM_E_IO, T(M_IO_RECV));
        int w = wait_sock(s, false, io->deadline);
        if (w == 0) return io_fail(io, err, TM_E_TIMEOUT, T(M_IO_TIMEOUT));
        if (w < 0) return io_fail(io, err, TM_E_IO, T(M_IO_RECV));
    }
}

int io_write(tm_io *io, const void *p, size_t n, tm_err *err)
{
    if (io->broken) return tm_fail(err, TM_E_IO, "%s", T(M_IO_CLOSED));
    if (io->tls) return tls_write(io->tls, p, n, err);
    const uint8_t *u = p;
    while (n) {
        int rc = io_raw_send(io, u, n, err);
        if (rc < 0) return -1;
        u += rc;
        n -= (size_t)rc;
    }
    return 0;
}

int io_read(tm_io *io, void *p, size_t n, tm_err *err)
{
    if (io->broken) return tm_fail(err, TM_E_IO, "%s", T(M_IO_CLOSED));
    uint8_t *u = p;
    while (n) {
        if (io->rpos == io->rlen && io->tls) {
            int rc = tls_read(io->tls, io->rbuf, sizeof io->rbuf, err);
            if (rc <= 0) return -1;
            io->rpos = 0;
            io->rlen = (size_t)rc;
        }
        if (io->rpos == io->rlen) {
            /* Pedidos grandes vão direto ao destino, sem passar pelo buffer. */
            if (n >= sizeof io->rbuf) {
                int rc = io_raw_recv(io, u, n, err);
                if (rc < 0) return -1;
                u += rc;
                n -= (size_t)rc;
                continue;
            }
            int rc = io_raw_recv(io, io->rbuf, sizeof io->rbuf, err);
            if (rc < 0) return -1;
            io->rpos = 0;
            io->rlen = (size_t)rc;
        }
        size_t take = io->rlen - io->rpos;
        if (take > n) take = n;
        memcpy(u, io->rbuf + io->rpos, take);
        io->rpos += take;
        u += take;
        n -= take;
    }
    return 0;
}

void io_close(tm_io *io)
{
    if (io->tls) {
        tls_free(io->tls);
        io->tls = NULL;
    }
    if ((sock_t)io->fd != SOCK_BAD) sock_close((sock_t)io->fd);
    io->fd = (intptr_t)SOCK_BAD;
    io->broken = true;
    io->rpos = io->rlen = 0;
}
