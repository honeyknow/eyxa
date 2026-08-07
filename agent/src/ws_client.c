/*
 * Eyxa persistent WebSocket client -- Phase 3 module 5.
 *
 * Maintains a persistent WebSocket connection to the backend for two
 * purposes:
 *
 *   RECEIVE  Response-action commands dispatched from the dashboard.
 *            Each inbound message is a JSON object with at minimum:
 *              {"type":"command","id":"<uuid>","action":"<verb>","target":{...}}
 *            The caller supplies a EYXA_CMD_CB callback that processes
 *            the raw JSON bytes.  This module does not interpret commands.
 *
 *   SEND     Live host statistics pushed every EYXA_WS_STATS_INTERVAL_MS.
 *            Format: {"type":"stats","ts":<unix_sec>,"cpu_pct":<0-100>,
 *                     "mem_total_mb":<uint>,"mem_free_mb":<uint>}
 *            CPU is sampled using GetSystemTimes (two reads separated by
 *            EYXA_CPU_SAMPLE_MS); memory via GlobalMemoryStatusEx.
 *            Sources:
 *              https://learn.microsoft.com/en-us/windows/win32/api/
 *                      sysinfoapi/nf-sysinfoapi-getsystemtimes
 *              https://learn.microsoft.com/en-us/windows/win32/api/
 *                      sysinfoapi/nf-sysinfoapi-globalmemorystatusex
 *
 * Transport
 * ── WinHTTP WebSocket (WinHttpWebSocketCompleteUpgrade, Send, Receive).
 *    Concurrent send + receive from separate threads IS supported per the
 *    WinHTTP docs ("a send and a receive may be performed simultaneously"),
 *    but two concurrent sends or two concurrent receives are not.  A
 *    CRITICAL_SECTION therefore serialises all sends so the recv thread
 *    and the stats timer thread cannot race on Send.
 *    Source: https://learn.microsoft.com/en-us/windows/win32/api/winhttp/
 *            nf-winhttp-winhttpwebsocketsend
 *
 * Reconnect
 * ── On disconnect or error, the recv thread sleeps for an exponentially
 *    increasing interval (1 s → 2 s → 4 s ... up to 60 s) before
 *    attempting to reconnect, so a backend restart does not storm the
 *    service.
 *
 * Endpoint
 *   wss://{host}:{port}/ws/agent/{agent_token}
 *   (scheme is derived by replacing https → wss, http → ws)
 *
 * Caller contract
 * ── enrollment must remain valid until EyxaWsClientStop returns.
 * ── The cmd_cb is called from the recv thread; it must be thread-safe
 *    and must return quickly (no blocking I/O inside).
 * ── Call EyxaWsClientStart once; do not call again without Stop.
 */

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0602
#include <windows.h>
#include <winhttp.h>
#include <shlobj.h>
#include <knownfolders.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "enrollment.c"
#include "stats.c"

/* ── tunables ──────────────────────────────────────────────────────── */
#define EYXA_WS_STATS_INTERVAL_MS  5000UL
#define EYXA_CPU_SAMPLE_MS         200UL
#define EYXA_WS_RECV_BUFFER        8192UL
#define EYXA_WS_RECONNECT_MAX_SEC  60UL
#define EYXA_WS_PATH_FMT           L"/ws/agent/%ls"
#define EYXA_WS_UA                 L"Eyxa-Agent/1.0"
#define EYXA_REGKEY_EYXA           L"SOFTWARE\\Eyxa"
#define EYXA_REGVAL_SKIP_TLS       L"SkipTlsVerify"

/* ── types ─────────────────────────────────────────────────────────── */

/*
 * Called from the recv thread for every inbound WebSocket message.
 * `data` is the raw UTF-8 JSON bytes; `len` is the byte count.
 * The callback must not free data; it is valid only for the duration of
 * the call.
 */
typedef void (*EYXA_CMD_CB)(const BYTE *data, DWORD len, void *context);

typedef struct {
    EYXA_ENROLLMENT  *enrollment;
    EYXA_CMD_CB       cmd_cb;
    void             *cmd_ctx;
    HANDLE            recv_thread;
    HANDLE            stats_thread;
    HANDLE            stop_event;
    CRITICAL_SECTION  send_lock;   /* serialises all WS sends */
    HINTERNET         ws;          /* current WebSocket handle; NULL = disconnected */
    volatile LONG     stopping;
    volatile LONG     failed;
    DWORD             last_error;
} EYXA_WS_CLIENT;

/* ── private helpers ───────────────────────────────────────────────── */

static DWORD EyxaWsReadRegDword(const WCHAR *subkey, const WCHAR *value)
{
    HKEY  key = NULL;
    DWORD type, data = 0, bytes = sizeof(data);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &key) != ERROR_SUCCESS)
        return 0;
    if (RegQueryValueExW(key, value, NULL, &type,
                         (LPBYTE)&data, &bytes) != ERROR_SUCCESS || type != REG_DWORD)
        data = 0;
    RegCloseKey(key);
    return data;
}

/*
 * Convert GetSystemTimes FILETIME values to a UINT64 of 100-ns intervals.
 * Macro avoids a function call in the hot sampling path.
 */
#define FT_TO_U64(ft) \
    (((UINT64)(ft).dwHighDateTime << 32) | (UINT64)(ft).dwLowDateTime)

/*
 * Build the WebSocket URL path from the agent token.
 * Result written to path_out (caller supplies MAX_PATH buffer).
 */
static BOOL EyxaBuildWsPath(const WCHAR *token, WCHAR *path_out, DWORD path_chars)
{
    return swprintf(path_out, path_chars, EYXA_WS_PATH_FMT, token) >= 0;
}

/*
 * Open a fresh WinHTTP WebSocket to the backend.
 * Returns the WS handle, or NULL on failure.
 * Handles both wss:// (443) and ws:// (80) backends.
 *
 * Upgrade flow per Microsoft docs:
 *   WinHttpOpenRequest → WinHttpSetOption(UPGRADE_TO_WEB_SOCKET) →
 *   WinHttpSendRequest → WinHttpReceiveResponse →
 *   WinHttpWebSocketCompleteUpgrade
 * Source: https://learn.microsoft.com/en-us/windows/win32/winhttp/
 *         winhttpsendrequest
 */
static HINTERNET EyxaWsConnect(EYXA_WS_CLIENT *c)
{
    URL_COMPONENTS comps;
    WCHAR   host[256], scheme[16], url_path[512];
    WCHAR   ws_path[512];
    WCHAR   full_url[1024];
    HINTERNET session = NULL, conn = NULL, req = NULL, ws = NULL;
    DWORD   flags = WINHTTP_FLAG_REFRESH;
    BOOL    secure;
    DWORD   skip_tls;

    /* Build full URL: backend_url + /ws/agent/{token} */
    if (!EyxaBuildWsPath(c->enrollment->agent_token,
                         ws_path, ARRAYSIZE(ws_path))) return NULL;
    if (swprintf(full_url, ARRAYSIZE(full_url), L"%ls%ls",
                 c->enrollment->backend_url, ws_path) < 0) return NULL;

    ZeroMemory(&comps, sizeof(comps));
    comps.dwStructSize      = sizeof(comps);
    comps.lpszScheme        = scheme;
    comps.dwSchemeLength    = ARRAYSIZE(scheme);
    comps.lpszHostName      = host;
    comps.dwHostNameLength  = ARRAYSIZE(host);
    comps.lpszUrlPath       = url_path;
    comps.dwUrlPathLength   = ARRAYSIZE(url_path);
    if (!WinHttpCrackUrl(full_url, 0, 0, &comps)) return NULL;

    /* Treat https/wss as secure. */
    secure = (_wcsicmp(scheme, L"https") == 0 || _wcsicmp(scheme, L"wss") == 0);
    if (secure) flags |= WINHTTP_FLAG_SECURE;

    session = WinHttpOpen(EYXA_WS_UA, WINHTTP_ACCESS_TYPE_NO_PROXY,
                          NULL, NULL, 0);
    if (!session) return NULL;

    conn = WinHttpConnect(session, host,
                          comps.nPort ? comps.nPort : (secure ? 443 : 80), 0);
    if (!conn) goto fail;

    /* WinHTTP WebSocket requires GET (the upgrade mechanism). */
    req = WinHttpOpenRequest(conn, L"GET", url_path, NULL,
                             WINHTTP_NO_REFERER,
                             WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!req) goto fail;

    skip_tls = EyxaWsReadRegDword(EYXA_REGKEY_EYXA, EYXA_REGVAL_SKIP_TLS);
    if (skip_tls) {
        DWORD ignore = SECURITY_FLAG_IGNORE_UNKNOWN_CA       |
                       SECURITY_FLAG_IGNORE_CERT_DATE_INVALID|
                       SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        WinHttpSetOption(req, WINHTTP_OPTION_SECURITY_FLAGS,
                         &ignore, sizeof(ignore));
    }

    /* Mark the request for WebSocket upgrade before sending. */
    if (!WinHttpSetOption(req, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET,
                          NULL, 0)) goto fail;

    if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            NULL, 0, 0, 0)) goto fail;
    if (!WinHttpReceiveResponse(req, NULL)) goto fail;

    ws = WinHttpWebSocketCompleteUpgrade(req, 0);
    if (!ws) goto fail;

    /* session and conn are freed independently; ws keeps refs internally. */
    WinHttpCloseHandle(req); req = NULL;
    WinHttpCloseHandle(conn); conn = NULL;
    WinHttpCloseHandle(session); session = NULL;
    return ws;

fail:
    if (req)     WinHttpCloseHandle(req);
    if (conn)    WinHttpCloseHandle(conn);
    if (session) WinHttpCloseHandle(session);
    return NULL;
}

/*
 * Send a UTF-8 message over the WebSocket.
 * Acquires send_lock so this is safe to call from any thread.
 */
static BOOL EyxaWsSend(EYXA_WS_CLIENT *c, const char *msg, DWORD len)
{
    BOOL ok = FALSE;
    EnterCriticalSection(&c->send_lock);
    if (c->ws != NULL) {
        DWORD result = WinHttpWebSocketSend(c->ws,
                           WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
                           (PVOID)msg, len);
        ok = (result == ERROR_SUCCESS);
    }
    LeaveCriticalSection(&c->send_lock);
    return ok;
}

/* ── stats sender thread ───────────────────────────────────────────── */

static DWORD WINAPI EyxaWsStatsThread(void *context)
{
    EYXA_WS_CLIENT *c = (EYXA_WS_CLIENT *)context;
    
    EyxaLiveStatsInit();

    for (;;) {
        DWORD wait = WaitForSingleObject(c->stop_event,
                                        EYXA_WS_STATS_INTERVAL_MS);
        if (InterlockedCompareExchange(&c->stopping, 0, 0)) break;
        if (wait == WAIT_OBJECT_0) break;

        /* ── sample host metrics ─────────────────────────────────── */
        {
            char msg[512];
            if (EyxaLiveStatsPoll(msg, sizeof(msg))) {
                EyxaWsSend(c, msg, (DWORD)strlen(msg));
            }
        }
    }
    return 0;
}

/* ── receive thread (also owns the connection lifecycle) ───────────── */

static DWORD WINAPI EyxaWsRecvThread(void *context)
{
    EYXA_WS_CLIENT *c = (EYXA_WS_CLIENT *)context;
    BYTE  *buf = NULL;
    DWORD  reconnect_sec = 1;
    DWORD  consecutive_fails = 0;

    /* H-6: Fragment reassembly buffer.
     * WinHTTP delivers fragmented WebSocket messages as one or more FRAGMENT
     * frames followed by a terminal MESSAGE frame.  Commands from the backend
     * can be split across frames on lossy / slow links.  We accumulate all
     * fragments here and dispatch only when the complete message arrives.
     * Source: https://learn.microsoft.com/en-us/windows/win32/api/winhttp/
     *         nf-winhttp-winhttpwebsocketreceive */
    BYTE  *frag_buf = NULL;
    DWORD  frag_len = 0;
    DWORD  frag_cap = 0;

    buf = (BYTE *)malloc(EYXA_WS_RECV_BUFFER);
    if (!buf) {
        InterlockedExchange(&c->failed, 1);
        return 1;
    }

    while (!InterlockedCompareExchange(&c->stopping, 0, 0)) {

        /* ── (re)connect ─────────────────────────────────────────────── */
        {
            HINTERNET ws = EyxaWsConnect(c);
            EnterCriticalSection(&c->send_lock);
            c->ws = ws;
            LeaveCriticalSection(&c->send_lock);

            if (!ws) {
                consecutive_fails++;
                /* L-5 fix: set failed after max backoff is reached AND a further
                 * attempt still fails, signalling a persistent backend outage.
                 * Reset to 0 on the next successful connect below. */
                if (reconnect_sec >= EYXA_WS_RECONNECT_MAX_SEC && consecutive_fails > 2)
                    InterlockedExchange(&c->failed, 1);

                /* Back-off before retry. */
                DWORD wait_ms = reconnect_sec * 1000UL;
                if (WaitForSingleObject(c->stop_event, wait_ms) == WAIT_OBJECT_0)
                    break;
                reconnect_sec = (reconnect_sec * 2 < EYXA_WS_RECONNECT_MAX_SEC)
                                    ? reconnect_sec * 2
                                    : EYXA_WS_RECONNECT_MAX_SEC;
                continue;
            }
            reconnect_sec = 1;    /* reset on successful connect */
            consecutive_fails = 0;
            InterlockedExchange(&c->failed, 0); /* L-5: clear failed on reconnect */
            frag_len = 0;         /* discard any partial fragment from last session */
            
            /* Send hardware inventory immediately on connect */
            {
                char inv_msg[8192];
                if (EyxaHardwareInventory(inv_msg, sizeof(inv_msg))) {
                    EyxaWsSend(c, inv_msg, (DWORD)strlen(inv_msg));
                }
            }
        }

        /* ── receive loop ──────────────────────────────────────────────── */
        for (;;) {
            DWORD   bytes_read = 0;
            WINHTTP_WEB_SOCKET_BUFFER_TYPE buf_type;
            DWORD   result = WinHttpWebSocketReceive(
                                 c->ws, buf, (DWORD)EYXA_WS_RECV_BUFFER,
                                 &bytes_read, &buf_type);

            if (result != ERROR_SUCCESS) break; /* disconnected / error */
            if (InterlockedCompareExchange(&c->stopping, 0, 0)) break;

            if (buf_type == WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE) {
                /* H-6: accumulate fragment into frag_buf */
                if (frag_len + bytes_read > frag_cap) {
                    DWORD new_cap = (frag_cap + bytes_read) * 2 + EYXA_WS_RECV_BUFFER;
                    BYTE *tmp = (BYTE *)realloc(frag_buf, new_cap);
                    if (!tmp) { frag_len = 0; continue; } /* OOM: drop fragment */
                    frag_buf = tmp; frag_cap = new_cap;
                }
                memcpy(frag_buf + frag_len, buf, bytes_read);
                frag_len += bytes_read;

            } else if (buf_type == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE) {
                /* H-6: terminal frame — dispatch reassembled message */
                if (frag_len > 0) {
                    /* R-1 fix: use a temp pointer to grow frag_buf so that
                     * frag_buf is NEVER set to NULL on realloc failure.
                     * Old code did (frag_buf = realloc(...)) which aliased
                     * frag_buf to NULL, leaving frag_cap stale and causing
                     * the next FRAGMENT frame to memcpy(NULL,...) -> crash. */
                    DWORD total    = frag_len + bytes_read;
                    BOOL  dispatch = TRUE;
                    if (total > frag_cap) {
                        BYTE *_tmp = (BYTE *)realloc(frag_buf, total + 1);
                        if (_tmp) { frag_buf = _tmp; frag_cap = total + 1; }
                        else      { dispatch = FALSE; } /* OOM: keep old alloc, drop message */
                    }
                    if (dispatch) {
                        memcpy(frag_buf + frag_len, buf, bytes_read);
                        if (c->cmd_cb) c->cmd_cb(frag_buf, total, c->cmd_ctx);
                    }
                    frag_len = 0; /* always reset accumulator */
                } else {
                    /* Standalone (non-fragmented) complete message — dispatch directly */
                    if (c->cmd_cb && bytes_read > 0)
                        c->cmd_cb(buf, bytes_read, c->cmd_ctx);
                }

            } else if (buf_type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) {
                frag_len = 0;
                break;
            }
        }

        /* ── clean up current connection ─────────────────────────────────── */
        {
            EnterCriticalSection(&c->send_lock);
            if (c->ws) {
                /* Attempt graceful close; ignore errors (we're disconnecting). */
                WinHttpWebSocketClose(c->ws,
                    WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, NULL, 0);
                WinHttpCloseHandle(c->ws);
                c->ws = NULL;
            }
            LeaveCriticalSection(&c->send_lock);
        }

        if (InterlockedCompareExchange(&c->stopping, 0, 0)) break;

        /* Brief pause before reconnect attempt. */
        if (WaitForSingleObject(c->stop_event, reconnect_sec * 1000UL)
                == WAIT_OBJECT_0)
            break;
        reconnect_sec = (reconnect_sec * 2 < EYXA_WS_RECONNECT_MAX_SEC)
                            ? reconnect_sec * 2
                            : EYXA_WS_RECONNECT_MAX_SEC;
    }

    /* Ensure ws is closed on the way out. */
    EnterCriticalSection(&c->send_lock);
    if (c->ws) {
        WinHttpWebSocketClose(c->ws,
            WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, NULL, 0);
        WinHttpCloseHandle(c->ws);
        c->ws = NULL;
    }
    LeaveCriticalSection(&c->send_lock);

    free(frag_buf);
    free(buf);
    return 0;
}

/* ── public API ────────────────────────────────────────────────────── */

BOOL EyxaWsClientStart(EYXA_WS_CLIENT *c,
                        EYXA_ENROLLMENT *enrollment,
                        EYXA_CMD_CB      cmd_cb,
                        void            *cmd_ctx)
{
    if (c == NULL || enrollment == NULL || !enrollment->enrolled) return FALSE;
    ZeroMemory(c, sizeof(*c));
    c->enrollment = enrollment;
    c->cmd_cb     = cmd_cb;
    c->cmd_ctx    = cmd_ctx;

    InitializeCriticalSection(&c->send_lock);

    c->stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!c->stop_event) goto fail;

    c->recv_thread = CreateThread(NULL, 0, EyxaWsRecvThread, c, 0, NULL);
    if (!c->recv_thread) goto fail;

    c->stats_thread = CreateThread(NULL, 0, EyxaWsStatsThread, c, 0, NULL);
    if (!c->stats_thread) goto fail;

    return TRUE;
fail:
    InterlockedExchange(&c->stopping, 1);
    if (c->stop_event) { SetEvent(c->stop_event); CloseHandle(c->stop_event); c->stop_event = NULL; }
    if (c->recv_thread)  { WaitForSingleObject(c->recv_thread,  5000); CloseHandle(c->recv_thread);  c->recv_thread = NULL; }
    if (c->stats_thread) { WaitForSingleObject(c->stats_thread, 5000); CloseHandle(c->stats_thread); c->stats_thread = NULL; }
    DeleteCriticalSection(&c->send_lock);
    return FALSE;
}

void EyxaWsClientStop(EYXA_WS_CLIENT *c)
{
    if (c == NULL) return;
    InterlockedExchange(&c->stopping, 1);
    if (c->stop_event) SetEvent(c->stop_event);
    if (c->recv_thread) {
        WaitForSingleObject(c->recv_thread,  10000);
        CloseHandle(c->recv_thread);
        c->recv_thread = NULL;
    }
    if (c->stats_thread) {
        WaitForSingleObject(c->stats_thread, 10000);
        CloseHandle(c->stats_thread);
        c->stats_thread = NULL;
    }
    if (c->stop_event) { CloseHandle(c->stop_event); c->stop_event = NULL; }
    DeleteCriticalSection(&c->send_lock);
}

BOOL EyxaWsClientFailed(const EYXA_WS_CLIENT *c, DWORD *last_error_out)
{
    if (!c) return TRUE;
    if (last_error_out) *last_error_out = c->last_error;
    return InterlockedCompareExchange((volatile LONG *)&c->failed, 0, 0) != 0;
}
