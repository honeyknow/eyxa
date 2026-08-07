#ifndef EYXA_ENROLLMENT_C
#define EYXA_ENROLLMENT_C
/*
 * Eyxa endpoint identity and enrollment -- Phase 3 module 6.
 *
 * Responsibilities
 * ── Derive a stable per-machine identifier from the Windows MachineGuid
 *    registry value (HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid).
 *    This GUID is assigned by Windows Setup, survives reboots and most
 *    software changes, and is the standard identifier used by Windows
 *    Update, telemetry, and enterprise management tooling.
 *    Source: https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/
 *            nf-sysinfoapi-getcomputernamew (for hostname)
 *    Source: https://learn.microsoft.com/en-us/windows/win32/sysinfo/
 *            registry (for MachineGuid path)
 *
 * ── On first run (no token file on disk), POST to the backend /api/enroll
 *    endpoint using WinHTTP.  WinHTTP is the correct choice for a Windows
 *    service running as SYSTEM because it does not require a user logon
 *    session (unlike WinINet).
 *    Source: https://learn.microsoft.com/en-us/windows/win32/winhttp/
 *            winhttp-vs-wininet
 *
 * ── Persist the server-issued agent_token atomically to
 *    ProgramData\Eyxa\agent-token.bin (write-tmp / rename pattern).
 *
 * ── On subsequent runs, load and verify the token file without
 *    contacting the backend.
 *
 * Backend URL configuration
 * ── Read HKLM\SOFTWARE\Eyxa\BackendUrl (REG_SZ, e.g.
 *    "https://192.168.1.10:8443").  Falls back to EYXA_DEFAULT_BACKEND_URL
 *    if the key is absent (useful for localhost testing).
 *
 * TLS verification
 * ── Certificate verification is always enabled by default.  Set registry
 *    value HKLM\SOFTWARE\Eyxa\SkipTlsVerify = 1 (REG_DWORD) only for
 *    local development against a self-signed certificate.
 *
 * Caller contract
 * ── Call EyxaEnrollmentInit once at agent startup before using sender or
 *    ws_client.  Call EyxaEnrollmentCleanup at shutdown.
 * ── EyxaEnrollmentToken / EyxaEnrollmentMachineId return pointers to
 *    internal WCHAR buffers valid until EyxaEnrollmentCleanup.
 */

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0602          /* Windows 8 -- WinHTTP WebSocket baseline */
#include <windows.h>
#include <winhttp.h>
#include <shlobj.h>
#include <knownfolders.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* ── constants ─────────────────────────────────────────────────────── */
#define EYXA_STATE_DIR_NAME      L"Eyxa"
#define EYXA_TOKEN_FILE_NAME     L"agent-token.bin"
#define EYXA_DEFAULT_BACKEND_URL L"https://localhost:8443"
#define EYXA_REGKEY_EYXA         L"SOFTWARE\\Eyxa"
#define EYXA_REGVAL_BACKEND_URL  L"BackendUrl"
#define EYXA_REGVAL_SKIP_TLS     L"SkipTlsVerify"
#define EYXA_REGVAL_ENROLL_TOKEN L"EnrollToken"  /* per-user token from download page */
#define EYXA_MACHINEGUID_REGKEY  L"SOFTWARE\\Microsoft\\Cryptography"
#define EYXA_MACHINEGUID_REGVAL  L"MachineGuid"
#define EYXA_ENROLL_PATH         L"/api/enroll"
#define EYXA_UA                  L"Eyxa-Agent/1.0"
#define EYXA_TOKEN_MAX_WCHARS    512

/* ── public types ──────────────────────────────────────────────────── */
typedef struct {
    WCHAR agent_token[EYXA_TOKEN_MAX_WCHARS];
    WCHAR machine_id[64];
    WCHAR hostname[MAX_COMPUTERNAME_LENGTH + 2];
    WCHAR backend_url[512];
    WCHAR enroll_token[512]; /* read from HKLM\SOFTWARE\Eyxa\EnrollToken at first run */
    BOOL  enrolled;
} EYXA_ENROLLMENT;

/* ── private helpers ───────────────────────────────────────────────── */

static BOOL EyxaBuildStatePath(WCHAR *path_out, DWORD path_chars,
                               const WCHAR *file_name)
{
    PWSTR  program_data = NULL;
    WCHAR  state_dir[MAX_PATH];
    HRESULT hr;
    BOOL   ok = FALSE;

    hr = SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, NULL, &program_data);
    if (FAILED(hr) || program_data == NULL) return FALSE;

    if (swprintf(state_dir, MAX_PATH, L"%ls\\%ls",
                 program_data, EYXA_STATE_DIR_NAME) < 0) goto done;
    if (!CreateDirectoryW(state_dir, NULL) &&
        GetLastError() != ERROR_ALREADY_EXISTS) goto done;
    if (swprintf(path_out, path_chars, L"%ls\\%ls",
                 state_dir, file_name) < 0) goto done;
    ok = TRUE;
done:
    CoTaskMemFree(program_data);
    return ok;
}

/* Read a REG_SZ value from HKLM into a caller-supplied WCHAR buffer. */
static BOOL EyxaReadRegSz(const WCHAR *subkey, const WCHAR *value,
                           WCHAR *buf, DWORD buf_chars)
{
    HKEY  key = NULL;
    DWORD type, bytes = buf_chars * sizeof(WCHAR);
    BOOL  ok = FALSE;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &key) != ERROR_SUCCESS)
        return FALSE;
    if (RegQueryValueExW(key, value, NULL, &type, (LPBYTE)buf, &bytes) == ERROR_SUCCESS
        && type == REG_SZ) {
        buf[buf_chars - 1] = L'\0';
        ok = TRUE;
    }
    RegCloseKey(key);
    return ok;
}

/* Read a REG_DWORD from HKLM; returns the value or 0 on error. */
static DWORD EyxaReadRegDword(const WCHAR *subkey, const WCHAR *value)
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
 * Atomically persist the agent token to disk (UTF-16 LE, no BOM).
 * Uses the same write-tmp / rename pattern as sysmon_reader.c bookmarks.
 */
static BOOL EyxaSaveToken(const WCHAR *path, const WCHAR *token)
{
    WCHAR  tmp[MAX_PATH];
    HANDLE f = INVALID_HANDLE_VALUE;
    DWORD  written = 0;
    size_t chars;
    BOOL   ok = FALSE;

    if (swprintf(tmp, MAX_PATH, L"%ls.tmp", path) < 0) return FALSE;
    f = CreateFileW(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return FALSE;
    chars = wcslen(token);
    if (chars > (MAXDWORD / sizeof(WCHAR))) goto done;
    if (!WriteFile(f, token, (DWORD)(chars * sizeof(WCHAR)), &written, NULL) ||
        written != (DWORD)(chars * sizeof(WCHAR)) || !FlushFileBuffers(f))
        goto done;
    CloseHandle(f);
    f = INVALID_HANDLE_VALUE;
    ok = MoveFileExW(tmp, path,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
done:
    if (f != INVALID_HANDLE_VALUE) CloseHandle(f);
    if (!ok) DeleteFileW(tmp);
    return ok;
}

/* Load an existing token from disk into e->agent_token. */
static BOOL EyxaLoadToken(EYXA_ENROLLMENT *e, const WCHAR *path)
{
    HANDLE       f;
    LARGE_INTEGER size;
    DWORD        read = 0;
    DWORD        chars;
    BOOL         ok = FALSE;

    f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
        return GetLastError() == ERROR_FILE_NOT_FOUND; /* first run */
    if (!GetFileSizeEx(f, &size) || size.QuadPart <= 0 ||
        size.QuadPart > (EYXA_TOKEN_MAX_WCHARS - 1) * (LONGLONG)sizeof(WCHAR) ||
        (size.QuadPart % sizeof(WCHAR)) != 0)
        goto done;
    chars = (DWORD)(size.QuadPart / sizeof(WCHAR));
    if (!ReadFile(f, e->agent_token,
                  (DWORD)(chars * sizeof(WCHAR)), &read, NULL) ||
        read != (DWORD)(chars * sizeof(WCHAR)))
        goto done;
    e->agent_token[chars] = L'\0';
    ok = wcslen(e->agent_token) > 0;
done:
    CloseHandle(f);
    return ok;
}

/*
 * Minimal JSON string-field extractor for ASCII-safe values (UUIDs, tokens).
 * Handles: "key": "value"  (no escape sequences required for these fields).
 */
static BOOL EyxaJsonGetStr(const WCHAR *json, const WCHAR *key,
                            WCHAR *buf, DWORD buf_chars)
{
    WCHAR        search[256];
    const WCHAR *p, *end;
    DWORD        len;

    if (swprintf(search, 256, L"\"%ls\"", key) < 0) return FALSE;
    p = wcsstr(json, search);
    if (!p) return FALSE;
    p += wcslen(search);
    while (*p == L' ' || *p == L'\t' || *p == L':' || *p == L' ') p++;
    if (*p != L'"') return FALSE;
    p++;                           /* skip opening quote */
    end = wcschr(p, L'"');
    if (!end) return FALSE;
    len = (DWORD)(end - p);
    if (len == 0 || len >= buf_chars) return FALSE;
    memcpy(buf, p, len * sizeof(WCHAR));
    buf[len] = L'\0';
    return TRUE;
}

/*
 * POST to {backend_url}/api/enroll with a JSON body and return the
 * server-issued agent_token into e->agent_token.
 *
 * The URL is cracked with WinHttpCrackUrl so we do not hand-roll HTTP
 * host/port/path parsing.
 * Source: https://learn.microsoft.com/en-us/windows/win32/api/winhttp/
 *         nf-winhttp-winhttpcrackurl
 */
static BOOL EyxaDoEnroll(EYXA_ENROLLMENT *e)
{
    URL_COMPONENTS comps;
    WCHAR  host[256], url_path[512], scheme[16];
    WCHAR  body_wide[1024];
    CHAR   body_utf8[2048];
    WCHAR  resp_wide[4096];
    BYTE   resp_raw[8192];
    DWORD  resp_total = 0, read = 0;
    HINTERNET session = NULL, conn = NULL, req = NULL;
    DWORD  flags = WINHTTP_FLAG_REFRESH;
    BOOL   secure;
    DWORD  skip_tls, status = 0, status_len = sizeof(status);
    int    wchars;
    BOOL   ok = FALSE;

    /* Fail fast if no enroll_token - the backend will reject it anyway   */
    /* but an early check produces a clearer failure mode.                */
    if (wcslen(e->enroll_token) == 0) return FALSE;

    /* ── crack the backend URL ─────────────────────────────────────── */

    ZeroMemory(&comps, sizeof(comps));
    comps.dwStructSize    = sizeof(comps);
    comps.lpszScheme      = scheme;
    comps.dwSchemeLength  = ARRAYSIZE(scheme);
    comps.lpszHostName    = host;
    comps.dwHostNameLength = ARRAYSIZE(host);
    comps.lpszUrlPath     = url_path;
    comps.dwUrlPathLength = ARRAYSIZE(url_path);

    /* Append the enroll path to whatever path the base URL has. */
    {
        WCHAR full_url[1024];
        if (swprintf(full_url, ARRAYSIZE(full_url), L"%ls%ls",
                     e->backend_url, EYXA_ENROLL_PATH) < 0) return FALSE;
        if (!WinHttpCrackUrl(full_url, 0, 0, &comps)) return FALSE;
    }
    secure = (_wcsicmp(scheme, L"https") == 0);
    if (secure) flags |= WINHTTP_FLAG_SECURE;

    /* ── build JSON request body ───────────────────────────────────── */
    /* enroll_token links this agent to the correct tenant (user_id).     */
    /* Source: Phase 4 approved multi-tenant enrollment design 2026-07-27. */
    if (swprintf(body_wide, ARRAYSIZE(body_wide),
                 L"{\"enroll_token\":\"%ls\",\"machine_id\":\"%ls\","
                 L"\"hostname\":\"%ls\",\"os_version\":\"windows\"}",
                 e->enroll_token, e->machine_id, e->hostname) < 0) return FALSE;

    {
        int n = WideCharToMultiByte(CP_UTF8, 0, body_wide, -1,
                                    body_utf8, (int)sizeof(body_utf8), NULL, NULL);
        if (n <= 0) return FALSE;
        /* n includes the null terminator; body length excludes it. */
    }

    /* ── WinHTTP flow ──────────────────────────────────────────────── */
    session = WinHttpOpen(EYXA_UA, WINHTTP_ACCESS_TYPE_NO_PROXY,
                          NULL, NULL, 0);
    if (!session) return FALSE;

    conn = WinHttpConnect(session, host,
                          comps.nPort ? comps.nPort : (secure ? 443 : 80), 0);
    if (!conn) goto done;

    req = WinHttpOpenRequest(conn, L"POST", url_path, NULL,
                             WINHTTP_NO_REFERER,
                             WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!req) goto done;

    /* Allow self-signed certs when the registry opt-in is set. */
    skip_tls = EyxaReadRegDword(EYXA_REGKEY_EYXA, EYXA_REGVAL_SKIP_TLS);
    if (skip_tls) {
        DWORD ignore = SECURITY_FLAG_IGNORE_UNKNOWN_CA       |
                       SECURITY_FLAG_IGNORE_CERT_DATE_INVALID|
                       SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        WinHttpSetOption(req, WINHTTP_OPTION_SECURITY_FLAGS,
                         &ignore, sizeof(ignore));
    }

    {
        DWORD body_len = (DWORD)strlen(body_utf8);
        if (!WinHttpSendRequest(req,
                L"Content-Type: application/json\r\n",
                (DWORD)-1,
                (LPVOID)body_utf8, body_len, body_len, 0))
            goto done;
    }
    if (!WinHttpReceiveResponse(req, NULL)) goto done;

    /* Check HTTP status; only 200 is a success. */
    if (!WinHttpQueryHeaders(req,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            NULL, &status, &status_len, NULL) || status != 200)
        goto done;

    /* Read response body (up to sizeof(resp_raw) - 1 bytes). */
    while (resp_total < sizeof(resp_raw) - 1) {
        if (!WinHttpReadData(req, resp_raw + resp_total,
                             (DWORD)(sizeof(resp_raw) - 1 - resp_total),
                             &read))
            break;
        if (read == 0) break;
        resp_total += read;
    }
    resp_raw[resp_total] = 0;

    /* Convert UTF-8 response to UTF-16 for wcsstr parsing. */
    wchars = MultiByteToWideChar(CP_UTF8, 0, (LPCCH)resp_raw, (int)resp_total,
                                 resp_wide, (int)ARRAYSIZE(resp_wide) - 1);
    if (wchars <= 0) goto done;
    resp_wide[wchars] = L'\0';

    ok = EyxaJsonGetStr(resp_wide, L"agent_token",
                        e->agent_token, EYXA_TOKEN_MAX_WCHARS);
done:
    if (req)     WinHttpCloseHandle(req);
    if (conn)    WinHttpCloseHandle(conn);
    if (session) WinHttpCloseHandle(session);
    return ok;
}

/* ── public API ────────────────────────────────────────────────────── */

/*
 * Initialise enrollment state.
 *
 * ── Reads the MachineGuid from the registry.
 * ── Loads the backend URL from HKLM\SOFTWARE\Eyxa\BackendUrl (or uses
 *    the compiled-in default).
 * ── If a token file already exists on disk, loads it.
 * ── Otherwise calls the backend /api/enroll endpoint and saves the
 *    returned token.
 *
 * Returns TRUE if e->agent_token is populated and ready to use.
 */
BOOL EyxaEnrollmentInit(EYXA_ENROLLMENT *e)
{
    WCHAR token_path[MAX_PATH];
    DWORD name_len;

    if (e == NULL) return FALSE;
    ZeroMemory(e, sizeof(*e));

    /* ── machine identifier ────────────────────────────────────────── */
    if (!EyxaReadRegSz(EYXA_MACHINEGUID_REGKEY, EYXA_MACHINEGUID_REGVAL,
                       e->machine_id, (DWORD)ARRAYSIZE(e->machine_id)))
        return FALSE;

    /* ── hostname ──────────────────────────────────────────────────── */
    name_len = (DWORD)ARRAYSIZE(e->hostname);
    if (!GetComputerNameW(e->hostname, &name_len)) return FALSE;

    /* ── backend URL ───────────────────────────────────────────────── */
    if (!EyxaReadRegSz(EYXA_REGKEY_EYXA, EYXA_REGVAL_BACKEND_URL,
                       e->backend_url, (DWORD)ARRAYSIZE(e->backend_url)))
        wcscpy_s(e->backend_url, (DWORD)ARRAYSIZE(e->backend_url),
                  EYXA_DEFAULT_BACKEND_URL);

    /* ── enroll token (required for first-run enrollment) ──────────── */
    EyxaReadRegSz(EYXA_REGKEY_EYXA, EYXA_REGVAL_ENROLL_TOKEN,
                  e->enroll_token, (DWORD)ARRAYSIZE(e->enroll_token));

    /* ── token file path ───────────────────────────────────────────── */
    if (!EyxaBuildStatePath(token_path, (DWORD)ARRAYSIZE(token_path),
                            EYXA_TOKEN_FILE_NAME))
        return FALSE;

    /* ── load or enroll ────────────────────────────────────────────── */
    if (!EyxaLoadToken(e, token_path)) {
        /* File exists but is corrupt or unreadable. */
        return FALSE;
    }

    if (wcslen(e->agent_token) == 0) {
        /* First run: enroll with the backend. */
        if (!EyxaDoEnroll(e)) return FALSE;
        if (!EyxaSaveToken(token_path, e->agent_token)) return FALSE;
    }

    e->enrolled = TRUE;
    return TRUE;
}

void EyxaEnrollmentCleanup(EYXA_ENROLLMENT *e)
{
    if (e == NULL) return;
    SecureZeroMemory(e->agent_token, sizeof(e->agent_token));
    ZeroMemory(e, sizeof(*e));
}

const WCHAR *EyxaEnrollmentToken(const EYXA_ENROLLMENT *e)
{
    return (e && e->enrolled) ? e->agent_token : NULL;
}

const WCHAR *EyxaEnrollmentMachineId(const EYXA_ENROLLMENT *e)
{
    return (e && e->enrolled) ? e->machine_id : NULL;
}

const WCHAR *EyxaEnrollmentHostname(const EYXA_ENROLLMENT *e)
{
    return (e && e->enrolled) ? e->hostname : NULL;
}

#endif /* EYXA_ENROLLMENT_C */
