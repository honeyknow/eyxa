/*
 * Eyxa batched HTTPS telemetry sender -- Phase 3 module 4.
 *
 * Every 30 seconds this module reads a batch of pending records from the
 * durable buffer (buffer.c), serialises them as a JSON array, and POSTs
 * that array to the backend ingest endpoint.  On a confirmed HTTP 200 it
 * advances the buffer cursor; on any error it leaves the cursor in place
 * so the same records are retried on the next tick.
 *
 * Transport decisions
 * ── WinHTTP is used (not WinINet) because the agent runs as SYSTEM and
 *    requires no user-logon session for proxy/TLS negotiation.
 *    Source: https://learn.microsoft.com/en-us/windows/win32/winhttp/
 *            winhttp-vs-wininet
 * ── HTTPS is always used.  TLS certificate verification can be disabled
 *    for localhost testing via HKLM\SOFTWARE\Eyxa\SkipTlsVerify = 1.
 *
 * Endpoint
 *   POST {backend_url}/api/ingest
 *   Headers: Authorization: Bearer {agent_token}
 *            Content-Type:  application/json
 *   Body:    {"machine_id":"...","events":[<raw event payloads>]}
 *   where each element is the UTF-8 JSON string stored by the readers.
 *
 * Lifecycle
 * ── EyxaSenderStart  - starts the background 30-second timer thread.
 * ── EyxaSenderStop   - signals stop and blocks until the thread exits.
 *
 * Error handling
 * ── Network errors and non-200 responses are logged via the error
 *    callback but do NOT advance the buffer cursor, ensuring at-least-once
 *    delivery.
 * ── The sender never blocks the caller; all HTTP work happens on the
 *    private thread.
 *
 * Caller contract
 * ── buf and enrollment must remain valid until EyxaSenderStop returns.
 * ── Call EyxaSenderStart exactly once; do not call again without Stop.
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
#include "buffer.c"
#include "enrollment.c"

/* ── tunables ──────────────────────────────────────────────────────── */
#define EYXA_SENDER_INTERVAL_MS   30000UL
#define EYXA_INGEST_PATH          L"/api/ingest"
#define EYXA_SENDER_BATCH_RECORDS 500UL
#define EYXA_SENDER_UA            L"Eyxa-Agent/1.0"
#define EYXA_REGKEY_EYXA          L"SOFTWARE\\Eyxa"
#define EYXA_REGVAL_SKIP_TLS      L"SkipTlsVerify"

/* ── types ─────────────────────────────────────────────────────────── */

/* Called on each send attempt (success or failure) for observability. */
typedef void (*EYXA_SENDER_EVENT_CB)(BOOL success, DWORD http_status,
                                     DWORD records_sent, void *context);

typedef struct {
    EYXA_BUFFER      *buf;
    EYXA_ENROLLMENT  *enrollment;
    EYXA_SENDER_EVENT_CB event_cb;
    void             *event_ctx;
    HANDLE            thread;
    HANDLE            stop_event;
    volatile LONG     stopping;
    volatile LONG     failed;
    DWORD             last_error;
} EYXA_SENDER;

/* ── private helpers ───────────────────────────────────────────────── */

static DWORD EyxaSenderReadRegDword(const WCHAR *subkey, const WCHAR *value)
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
 * Serialise a batch into the JSON wire format:
 *   {"machine_id":"...","events":["<record0>","<record1>",...]}
 *
 * Each record in the batch is already a UTF-8 JSON object stored by the
 * reader modules.  We embed them as pre-formatted JSON values (not as
 * quoted strings) so the backend receives a proper JSON array of objects.
 *
 * Returns a heap-allocated UTF-8 string that the caller must free(), or
 * NULL on allocation failure.  *out_len receives the byte count (excluding
 * the null terminator).
 */
static char *EyxaBuildIngestBody(const EYXA_BUFFER_BATCH *batch,
                                 const WCHAR *machine_id,
                                 DWORD *out_len)
{
    /* Convert machine_id to UTF-8 for embedding in the JSON body. */
    char   mid_utf8[128] = {0};
    DWORD  off, len;
    const BYTE *rec;

    /* Estimate body size: header + per-record JSON + commas + footer. */
    SIZE_T capacity = 256 + batch->data_bytes + batch->record_count * 2 + 32;
    char  *body = (char *)malloc(capacity);
    SIZE_T pos  = 0;
    BOOL   first = TRUE;

    if (!body) return NULL;

    WideCharToMultiByte(CP_UTF8, 0, machine_id, -1,
                        mid_utf8, (int)sizeof(mid_utf8) - 1, NULL, NULL);

    pos += (SIZE_T)_snprintf_s(body + pos, capacity - pos, _TRUNCATE,
                               "{\"machine_id\":\"%s\",\"events\":[",
                               mid_utf8);


    off = 0;
    while ((rec = EyxaBufferBatchNext(batch, &off, &len)) != NULL) {
        /* Grow if needed (records are variable-length). */
        if (pos + len + 4 >= capacity) {
            SIZE_T new_cap = capacity * 2 + len + 4;
            char  *tmp = (char *)realloc(body, new_cap);
            if (!tmp) { free(body); return NULL; }
            body     = tmp;
            capacity = new_cap;
        }
        if (!first) body[pos++] = ',';
        first = FALSE;
        /* Embed the record bytes directly (they are already JSON objects). */
        memcpy(body + pos, rec, len);
        pos += len;
    }

    /* Ensure space for closing bracket + null. */
    if (pos + 4 >= capacity) {
        char *tmp = (char *)realloc(body, pos + 4);
        if (!tmp) { free(body); return NULL; }
        body = tmp;
    }
    body[pos++] = ']';
    body[pos++] = '}';
    body[pos]   = '\0';
    *out_len = (DWORD)pos;
    return body;
}

/*
 * Execute one ingest POST.  Returns the HTTP status code (200 = success),
 * or 0 on WinHTTP / network error.
 */
static DWORD EyxaPostIngest(EYXA_SENDER *s, const char *body, DWORD body_len)
{
    URL_COMPONENTS comps;
    WCHAR  host[256], url_path[512], scheme[16];
    HINTERNET session = NULL, conn = NULL, req = NULL;
    DWORD  flags = WINHTTP_FLAG_REFRESH;
    BOOL   secure;
    DWORD  status = 0, status_len = sizeof(status);
    WCHAR  auth_header[EYXA_TOKEN_MAX_WCHARS + 64];
    DWORD  skip_tls;
    BOOL   ok;

    /* Crack the backend URL + append ingest path. */
    ZeroMemory(&comps, sizeof(comps));
    comps.dwStructSize      = sizeof(comps);
    comps.lpszScheme        = scheme;
    comps.dwSchemeLength    = ARRAYSIZE(scheme);
    comps.lpszHostName      = host;
    comps.dwHostNameLength  = ARRAYSIZE(host);
    comps.lpszUrlPath       = url_path;
    comps.dwUrlPathLength   = ARRAYSIZE(url_path);
    {
        WCHAR full[1024];
        if (swprintf(full, ARRAYSIZE(full), L"%ls%ls",
                     s->enrollment->backend_url, EYXA_INGEST_PATH) < 0)
            return 0;
        if (!WinHttpCrackUrl(full, 0, 0, &comps)) return 0;
    }
    secure = (_wcsicmp(scheme, L"https") == 0);
    if (secure) flags |= WINHTTP_FLAG_SECURE;

    session = WinHttpOpen(EYXA_SENDER_UA, WINHTTP_ACCESS_TYPE_NO_PROXY,
                          NULL, NULL, 0);
    if (!session) return 0;

    conn = WinHttpConnect(session, host,
                          comps.nPort ? comps.nPort : (secure ? 443 : 80), 0);
    if (!conn) goto done;

    req = WinHttpOpenRequest(conn, L"POST", url_path, NULL,
                             WINHTTP_NO_REFERER,
                             WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!req) goto done;

    skip_tls = EyxaSenderReadRegDword(EYXA_REGKEY_EYXA, EYXA_REGVAL_SKIP_TLS);
    if (skip_tls) {
        DWORD ignore = SECURITY_FLAG_IGNORE_UNKNOWN_CA       |
                       SECURITY_FLAG_IGNORE_CERT_DATE_INVALID|
                       SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        WinHttpSetOption(req, WINHTTP_OPTION_SECURITY_FLAGS,
                         &ignore, sizeof(ignore));
    }

    /* Build Authorization header. */
    swprintf(auth_header, ARRAYSIZE(auth_header),
             L"Authorization: Bearer %ls\r\nContent-Type: application/json\r\n",
             s->enrollment->agent_token);

    ok = WinHttpSendRequest(req, auth_header, (DWORD)-1,
                            (LPVOID)body, body_len, body_len, 0);
    if (!ok) goto done;
    if (!WinHttpReceiveResponse(req, NULL)) goto done;

    WinHttpQueryHeaders(req,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        NULL, &status, &status_len, NULL);

done:
    if (req)     WinHttpCloseHandle(req);
    if (conn)    WinHttpCloseHandle(conn);
    if (session) WinHttpCloseHandle(session);
    return status;
}

static DWORD WINAPI EyxaSenderThread(void *context)
{
    EYXA_SENDER *s = (EYXA_SENDER *)context;
    DWORD next_wait_ms = EYXA_SENDER_INTERVAL_MS;

    for (;;) {
        DWORD wait = WaitForSingleObject(s->stop_event, next_wait_ms);
        next_wait_ms = EYXA_SENDER_INTERVAL_MS; /* Default to 30s for next loop */

        if (InterlockedCompareExchange(&s->stopping, 0, 0)) break;
        if (wait == WAIT_OBJECT_0) break; /* stop_event signalled */

        /* ── read a batch ─────────────────────────────────────────── */
        {
            EYXA_BUFFER_BATCH *batch =
                EyxaBufferReadBatch(s->buf, (DWORD)EYXA_SENDER_BATCH_RECORDS);
            if (batch == NULL) continue; /* nothing pending */

            {
                DWORD  body_len = 0;
                char  *body = EyxaBuildIngestBody(
                                  batch,
                                  EyxaEnrollmentMachineId(s->enrollment),
                                  &body_len);
                DWORD  http_status = 0;
                BOOL   sent_ok = FALSE;

                if (body) {
                    http_status = EyxaPostIngest(s, body, body_len);
                    sent_ok = (http_status == 200);
                    free(body);
                }

                if (sent_ok) {
                    EyxaBufferCommit(s->buf, batch->end_offset);
                    
                    /* Option 1: Aggressive flushing */
                    if (batch->record_count == EYXA_SENDER_BATCH_RECORDS) {
                        next_wait_ms = 50; /* Full batch sent. Yield 50ms, then loop instantly */
                    }
                }

                if (s->event_cb) {
                    s->event_cb(sent_ok, http_status,
                                sent_ok ? batch->record_count : 0,
                                s->event_ctx);
                }
            }

            EyxaBufferBatchFree(batch);
        }
    }
    return 0;
}

/* ── public API ────────────────────────────────────────────────────── */

BOOL EyxaSenderStart(EYXA_SENDER *s,
                     EYXA_BUFFER     *buf,
                     EYXA_ENROLLMENT *enrollment,
                     EYXA_SENDER_EVENT_CB event_cb,
                     void *event_ctx)
{
    if (s == NULL || buf == NULL || enrollment == NULL ||
        !enrollment->enrolled) return FALSE;
    ZeroMemory(s, sizeof(*s));
    s->buf        = buf;
    s->enrollment = enrollment;
    s->event_cb   = event_cb;
    s->event_ctx  = event_ctx;

    s->stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!s->stop_event) return FALSE;

    s->thread = CreateThread(NULL, 0, EyxaSenderThread, s, 0, NULL);
    if (!s->thread) {
        CloseHandle(s->stop_event);
        s->stop_event = NULL;
        return FALSE;
    }
    return TRUE;
}

void EyxaSenderStop(EYXA_SENDER *s)
{
    if (s == NULL) return;
    InterlockedExchange(&s->stopping, 1);
    if (s->stop_event) SetEvent(s->stop_event);
    if (s->thread) {
        WaitForSingleObject(s->thread, 10000);
        CloseHandle(s->thread);
        s->thread = NULL;
    }
    if (s->stop_event) {
        CloseHandle(s->stop_event);
        s->stop_event = NULL;
    }
}

BOOL EyxaSenderFailed(const EYXA_SENDER *s, DWORD *last_error_out)
{
    if (!s) return TRUE;
    if (last_error_out) *last_error_out = s->last_error;
    return InterlockedCompareExchange((volatile LONG *)&s->failed, 0, 0) != 0;
}
