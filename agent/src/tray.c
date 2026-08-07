/*
 * tray.c -- Eyxa EDR tray monitor, watchdog, and alert notifier.
 *
 * Responsibilities:
 *   - Shows a system tray icon reflecting real-time agent health
 *   - Pops balloon notifications when critical alerts arrive via shared memory
 *   - Watchdog: polls EyxaEDR service every 10s and restarts it if stopped
 *
 * Runs in the user session (Session 1+) at user login. Must be launched at
 * medium integrity (via Explorer or a logon task) -- NOT directly from an
 * elevated process. Shell_NotifyIconW messages are blocked by UIPI when
 * the caller is high integrity and Explorer is medium integrity.
 *
 * Communication with eyxa.exe (SYSTEM, Session 0):
 *   Reads "Global\EyxaStatusBlock" named shared memory written by eyxa.exe.
 *   Source: https://learn.microsoft.com/en-us/windows/win32/memory/creating-named-shared-memory
 *
 * Tray icon API:
 *   Source: https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shell_notifyiconw
 *
 * Build (x64 Native Tools Command Prompt):
 *   cl.exe /nologo /W3 /O2 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0602 ^
 *       /Fo"c:\product\garbage\\" ^
 *       "c:\product\eyxa\agent\src\tray.c" ^
 *       /Fe:"c:\product\eyxa\installer\terminator.exe" ^
 *       /link /SUBSYSTEM:WINDOWS advapi32.lib shell32.lib user32.lib kernel32.lib
 */

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0602
#include <windows.h>
#include <shellapi.h>
#include <winsvc.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "shared_status.h"

/* ── Constants ───────────────────────────────────────────────────────── */
#define WM_TRAYICON          (WM_APP + 1)
#define IDM_OPEN_DASHBOARD   101
#define IDM_VIEW_STATUS      102
#define IDM_RESTART_AGENT    103
#define IDM_STOP_AGENT       105
#define IDM_EXIT             104
#define IDM_CHANGE_SERVER    106
#define IDM_CONSOLE_MODE     107
#define TRAY_UID             1

#define WATCHDOG_TIMER_ID    1
#define WATCHDOG_INTERVAL_MS 10000   /* check service every 10 s */
#define POLL_TIMER_ID        2
#define POLL_INTERVAL_MS     5000    /* read shared mem every 5 s */

#define SVC_NAME             L"EyxaEDR"
#define DASHBOARD_URL        L"https://localhost:8443"
#define REGKEY_EYXA          L"SOFTWARE\\Eyxa"
#define REGVAL_BACKEND       L"BackendUrl"
#define REGVAL_ENROLL        L"EnrollToken"
#define WNDCLASS_NAME        L"EyxaTerminatorClass"
#define INSTANCE_MUTEX       L"Local\\EyxaTerminatorMutex"
#define LOG_PATH             L"C:\\ProgramData\\Eyxa\\terminator.log"

/* Watchdog restart throttle */
#define MAX_RESTARTS         3
#define RESTART_COOLDOWN_SEC 300

/* ── Globals ─────────────────────────────────────────────────────────── */
static HWND               g_hwnd         = NULL;
static NOTIFYICONDATAW    g_nid          = {0};
static HANDLE             g_shm_map      = NULL;
static EYXA_SHARED_STATUS *g_shm         = NULL;
static EYXA_HEALTH        g_last_health  = EYXA_HEALTH_STARTING;
static WCHAR              g_last_alert[128] = {0};
static int                g_restart_count   = 0;
static DWORD              g_last_restart_tick = 0;
static HANDLE             g_mutex        = NULL;
static UINT               g_taskbar_msg  = 0;
static BOOL               g_first_batch_notified = FALSE; /* fire once when first batch is sent */
static BOOL               g_user_stopped = FALSE;         /* user explicitly stopped agent - suppress watchdog restart */
static BOOL               g_restarting   = FALSE;         /* manual restart in progress - suppress watchdog */
static BOOL               g_was_offline  = FALSE;         /* tracks server connection state */

/* ── Startup log ─────────────────────────────────────────────────────── */
static void Log(const wchar_t *fmt, ...)
{
    FILE      *fp  = NULL;
    SYSTEMTIME st;
    wchar_t    buf[1024];
    va_list    ap;

    GetSystemTime(&st);
    va_start(ap, fmt);
    _vsnwprintf_s(buf, ARRAYSIZE(buf), _TRUNCATE, fmt, ap);
    va_end(ap);

    /* Source: https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/fopen-s-wfopen-s */
    if (_wfopen_s(&fp, LOG_PATH, L"a") == 0 && fp) {
        fwprintf(fp, L"[%04d-%02d-%02dT%02d:%02d:%02dZ] %ls\n",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond, buf);
        fclose(fp);
    }
}

/* ── Load a stock shell icon for the given health state ──────────────
 * Source: https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shgetstockiconinfo */
static HICON HealthIcon(EYXA_HEALTH h)
{
    SHSTOCKICONINFO sii  = {0};
    SHSTOCKICONID   siid;

    switch (h) {
        case EYXA_HEALTH_OK:       siid = SIID_SHIELD;  break;
        case EYXA_HEALTH_DEGRADED: siid = SIID_WARNING; break;
        case EYXA_HEALTH_ERROR:    siid = SIID_WARNING; break; /* User requested same yellow warning triangle for crashes */
        default:                   siid = SIID_SHIELD;  break;
    }

    sii.cbSize = sizeof(sii);
    if (SHGetStockIconInfo(siid, SHGSI_ICON | SHGSI_SMALLICON, &sii) == S_OK)
        return sii.hIcon;

    return LoadIconW(NULL, IDI_APPLICATION); /* fallback */
}

/* ── Create a badged version of the shield for offline status ────────── */
static HICON CreateOfflineBadgedIcon(HICON hBase)
{
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    
    BITMAPINFO bmi = {0};
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = 16;
    bmi.bmiHeader.biHeight = -16;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;
    
    void *bits;
    HBITMAP hbmp = CreateDIBSection(hdcScreen, &bmi, DIB_RGB_COLORS, &bits, NULL, 0);
    HBITMAP hOldBmp = (HBITMAP)SelectObject(hdcMem, hbmp);
    
    /* Draw base icon */
    DrawIconEx(hdcMem, 0, 0, hBase, 16, 16, 0, NULL, DI_NORMAL);
    
    /* Load and draw small warning badge */
    SHSTOCKICONINFO sii = {0};
    sii.cbSize = sizeof(sii);
    if (SHGetStockIconInfo(SIID_WARNING, SHGSI_ICON | SHGSI_SMALLICON, &sii) == S_OK) {
        DrawIconEx(hdcMem, 8, 8, sii.hIcon, 8, 8, 0, NULL, DI_NORMAL);
        DestroyIcon(sii.hIcon);
    }
    
    ICONINFO ii = {0};
    ii.fIcon = TRUE;
    ii.hbmColor = hbmp;
    ii.hbmMask = CreateBitmap(16, 16, 1, 1, NULL); /* Empty mask, use alpha from 32bpp */
    
    HICON hBadged = CreateIconIndirect(&ii);
    
    DeleteObject(ii.hbmMask);
    SelectObject(hdcMem, hOldBmp);
    DeleteObject(hbmp);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    
    return hBadged;
}

/* ── Update tray icon and tooltip ────────────────────────────────────── */
static void SetTrayIcon(EYXA_HEALTH health, BOOL is_offline, const WCHAR *tip)
{
    HICON icon = HealthIcon(health);
    
    if (health == EYXA_HEALTH_OK && is_offline) {
        HICON badged = CreateOfflineBadgedIcon(icon);
        if (badged) {
            DestroyIcon(icon);
            icon = badged;
        }
    }

    g_nid.uFlags = NIF_ICON | NIF_TIP;
    if (icon) g_nid.hIcon = icon;

    if (tip) {
        wcsncpy_s(g_nid.szTip, ARRAYSIZE(g_nid.szTip), tip, _TRUNCATE);
    } else {
        const WCHAR *s;
        switch (health) {
            case EYXA_HEALTH_OK:       
                s = is_offline ? L"Eyxa EDR - Server Offline (Buffering Events)" : L"Eyxa EDR - Healthy";   
                break;
            case EYXA_HEALTH_DEGRADED: s = L"Eyxa EDR - Degraded";  break;
            case EYXA_HEALTH_ERROR:    s = L"Eyxa EDR - Error!";    break;
            default:                   s = L"Eyxa EDR - Starting..."; break;
        }
        wcscpy_s(g_nid.szTip, ARRAYSIZE(g_nid.szTip), s);
    }

    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
    if (icon) DestroyIcon(icon);
    g_last_health = health;
}

/* ── Show a balloon notification ─────────────────────────────────────
 * Source: https://learn.microsoft.com/en-us/windows/win32/api/shellapi/ns-shellapi-notifyicondataw */
static void Balloon(const WCHAR *title, const WCHAR *body, DWORD icon_flag)
{
    g_nid.uFlags      = NIF_INFO;
    g_nid.dwInfoFlags = icon_flag | NIIF_NOSOUND;
    wcsncpy_s(g_nid.szInfoTitle, ARRAYSIZE(g_nid.szInfoTitle), title, _TRUNCATE);
    wcsncpy_s(g_nid.szInfo,      ARRAYSIZE(g_nid.szInfo),      body,  _TRUNCATE);
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

/* ── Open shared memory written by eyxa.exe ──────────────────────────
 * Source: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-openfilemappingw */
static void TryOpenSharedMem(void)
{
    if (g_shm) return;

    g_shm_map = OpenFileMappingW(FILE_MAP_READ, FALSE, EYXA_STATUS_MAP_NAME);
    if (!g_shm_map) return;

    g_shm = (EYXA_SHARED_STATUS *)MapViewOfFile(
                g_shm_map, FILE_MAP_READ, 0, 0, EYXA_STATUS_MAP_SIZE);
    if (!g_shm) {
        CloseHandle(g_shm_map);
        g_shm_map = NULL;
    }
}

/* ── Seqlock reader: plain volatile reads on read-only mapped memory ─
 *
 * IMPORTANT: Do NOT use InterlockedCompareExchange here.
 * The mapped view is FILE_MAP_READ (read-only pages). On x86-64, LOCK CMPXCHG
 * performs a locked read-modify-write bus cycle. The CPU checks page writability
 * BEFORE the comparison, so it raises STATUS_ACCESS_VIOLATION (0xC0000005) on
 * any read-only page, regardless of whether the values match.
 * A seqlock READER only needs a volatile read + MemoryBarrier -- no atomic write.
 *
 * Source: https://learn.microsoft.com/en-us/windows/win32/sync/interlocked-variable-access
 * Source: https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants */
static BOOL ReadStatus(EYXA_SHARED_STATUS *out)
{
    LONG seq1, seq2;
    int  i;

    if (!g_shm) return FALSE;

    for (i = 0; i < 5; i++) {
        seq1 = *(volatile LONG *)&g_shm->seq_begin;  /* volatile read, no write */
        seq2 = *(volatile LONG *)&g_shm->seq_end;
        if (seq1 != seq2) { Sleep(1); continue; }    /* write in progress */
        MemoryBarrier();
        CopyMemory(out, g_shm, sizeof(*out));
        MemoryBarrier();
        if (seq1 == *(volatile LONG *)&g_shm->seq_begin) return TRUE; /* consistent read */
        Sleep(1);
    }
    return FALSE;
}

/* ── Read backend URL from registry (fallback: DASHBOARD_URL) ───────── */
static void GetBackendUrl(WCHAR *out, DWORD chars)
{
    HKEY  key  = NULL;
    DWORD type, bytes = chars * sizeof(WCHAR);

    wcscpy_s(out, chars, DASHBOARD_URL);

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, REGKEY_EYXA, 0, KEY_READ, &key) == ERROR_SUCCESS) {
        if (RegQueryValueExW(key, REGVAL_BACKEND, NULL, &type, (LPBYTE)out, &bytes) != ERROR_SUCCESS)
            wcscpy_s(out, chars, DASHBOARD_URL);
        RegCloseKey(key);
    }
}

/* ── Extract just the host:port from a https://host:port URL ─────────── */
static void UrlToHost(const WCHAR *url, WCHAR *host, DWORD chars)
{
    const WCHAR *p = url;
    if (wcsncmp(p, L"https://", 8) == 0) p += 8;
    wcsncpy_s(host, chars, p, _TRUNCATE);
}

/* ── Read enroll token from registry ─────────────────────────────────── */
static void GetEnrollToken(WCHAR *out, DWORD chars)
{
    HKEY  key  = NULL;
    DWORD type, bytes = chars * sizeof(WCHAR);
    wcscpy_s(out, chars, L"(not set)");
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, REGKEY_EYXA, 0, KEY_READ, &key) == ERROR_SUCCESS) {
        if (RegQueryValueExW(key, REGVAL_ENROLL, NULL, &type, (LPBYTE)out, &bytes) != ERROR_SUCCESS)
            wcscpy_s(out, chars, L"(not set)");
        RegCloseKey(key);
    }
}

/* ── Write backend URL to registry (requires elevation) ─────────────── */
/* Source: https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexw */
static BOOL SetBackendUrl(const WCHAR *url)
{
    HKEY  key = NULL;
    BOOL  ok  = FALSE;
    DWORD disp;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, REGKEY_EYXA, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL,
                        &key, &disp) == ERROR_SUCCESS) {
        DWORD bytes = (DWORD)((wcslen(url) + 1) * sizeof(WCHAR));
        ok = (RegSetValueExW(key, REGVAL_BACKEND, 0, REG_SZ,
                             (const BYTE *)url, bytes) == ERROR_SUCCESS);
        RegCloseKey(key);
    }
    return ok;
}

/* ── Simple input dialog state ───────────────────────────────────────── */
typedef struct { const WCHAR *prompt; WCHAR result[256]; BOOL ok; } INPUT_DLG;

static LRESULT CALLBACK InputDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    /* Controls: ID 10 = static label, ID 11 = edit box, IDOK = 1, IDCANCEL = 2 */
    switch (msg) {
    case WM_CREATE: {
        INPUT_DLG *d = (INPUT_DLG *)((CREATESTRUCTW *)lp)->lpCreateParams;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)d);
        CreateWindowExW(0, L"STATIC", d->prompt,
            WS_CHILD|WS_VISIBLE, 10,10,340,20, hwnd, (HMENU)10, NULL, NULL);
        CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", d->result,
            WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL, 10,36,340,24, hwnd, (HMENU)11, NULL, NULL);
        CreateWindowExW(0, L"BUTTON", L"OK",
            WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON, 180,72,80,26, hwnd, (HMENU)IDOK, NULL, NULL);
        CreateWindowExW(0, L"BUTTON", L"Cancel",
            WS_CHILD|WS_VISIBLE, 270,72,80,26, hwnd, (HMENU)IDCANCEL, NULL, NULL);
        SetFocus(GetDlgItem(hwnd, 11));
        SendMessageW(GetDlgItem(hwnd, 11), EM_SETSEL, 0, -1);
        return 0;
    }
    case WM_COMMAND: {
        INPUT_DLG *d = (INPUT_DLG *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
        if (LOWORD(wp) == IDOK) {
            GetWindowTextW(GetDlgItem(hwnd, 11), d->result, ARRAYSIZE(d->result));
            d->ok = TRUE;
            DestroyWindow(hwnd);
        } else if (LOWORD(wp) == IDCANCEL) {
            DestroyWindow(hwnd);
        }
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

/* ── Prompt user for a new server IP and save it ─────────────────────── */
static void ChangeServerIp(void)
{
    WCHAR           cur_url[256], cur_host[256], new_url[256];
    INPUT_DLG       d = {0};
    WNDCLASSEXW     wc = {0};
    HINSTANCE       hInst = GetModuleHandleW(NULL);
    HWND            dlg;
    MSG             msg;

    GetBackendUrl(cur_url, ARRAYSIZE(cur_url));
    UrlToHost(cur_url, cur_host, ARRAYSIZE(cur_host));

    /* Sanitize pre-fill: if there are two colons (double-port bug from old saves),
     * strip everything from the second colon onward. */
    {
        WCHAR *p1 = wcschr(cur_host, L':');
        if (p1) {
            WCHAR *p2 = wcschr(p1 + 1, L':');
            if (p2) *p2 = L'\0';
        }
    }

    d.prompt = L"Enter new server IP or hostname:";
    wcsncpy_s(d.result, ARRAYSIZE(d.result), cur_host, _TRUNCATE);
    d.ok = FALSE;

    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = InputDlgProc;
    wc.hInstance     = hInst;
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"EyxaInputDlg";
    wc.hCursor       = LoadCursorW(NULL, IDC_ARROW);
    RegisterClassExW(&wc); /* ignore duplicate registration error */

    dlg = CreateWindowExW(WS_EX_DLGMODALFRAME | WS_EX_TOPMOST,
                          L"EyxaInputDlg", L"Eyxa EDR - Change Server",
                          WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
                          CW_USEDEFAULT, CW_USEDEFAULT, 374, 140,
                          NULL, NULL, hInst, &d);
    if (!dlg) return;
    ShowWindow(dlg, SW_SHOW);
    UpdateWindow(dlg);

    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    if (!d.ok || d.result[0] == L'\0') return;

    /* If user typed host:port, use it verbatim; if just host, append :8443 */
    if (wcschr(d.result, L':'))
        _snwprintf_s(new_url, ARRAYSIZE(new_url), _TRUNCATE, L"https://%ls", d.result);
    else
        _snwprintf_s(new_url, ARRAYSIZE(new_url), _TRUNCATE, L"https://%ls:8443", d.result);

    /* Writing HKLM requires elevation -- spawn elevated cmd.exe to do it. */
    WCHAR cmd[512];
    _snwprintf_s(cmd, ARRAYSIZE(cmd), _TRUNCATE,
        L"/c reg add \"HKLM\\SOFTWARE\\Eyxa\" /v BackendUrl /t REG_SZ /d \"%ls\" /f",
        new_url);
    SHELLEXECUTEINFOW sei = {0};
    sei.cbSize       = sizeof(sei);
    sei.fMask        = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb       = L"runas";
    sei.lpFile       = L"cmd.exe";
    sei.lpParameters = cmd;
    sei.nShow        = SW_HIDE;
    if (ShellExecuteExW(&sei)) {
        if (sei.hProcess) { WaitForSingleObject(sei.hProcess, 5000); CloseHandle(sei.hProcess); }
        WCHAR balloon[256];
        _snwprintf_s(balloon, ARRAYSIZE(balloon), _TRUNCATE,
            L"Server changed to %ls. Restart agent to apply.", d.result);
        Balloon(L"Eyxa EDR - Server Updated", balloon, NIIF_INFO);
    } else {
        Balloon(L"Eyxa EDR - Change Failed", L"Could not update registry. UAC was denied.", NIIF_ERROR);
    }
}

/* ── Open dashboard in default browser ──────────────────────────────── */
static void OpenDashboard(void)
{
    WCHAR url[256];
    GetBackendUrl(url, ARRAYSIZE(url));
    ShellExecuteW(NULL, L"open", url, NULL, NULL, SW_SHOWNORMAL);
}

/* ── Show status details in a message box ────────────────────────────── */
static void ShowStatusBox(void)
{
    EYXA_SHARED_STATUS s = {0};
    WCHAR msg[512];

    if (!ReadStatus(&s)) {
        MessageBoxW(NULL,
            L"Cannot read agent status.\n\n"
            L"EyxaEDR service may not be running.\n"
            L"Open services.msc and verify EyxaEDR is started.",
            L"Eyxa EDR - No Status", MB_OK | MB_ICONWARNING);
        return;
    }

    const WCHAR *hs;
    switch (s.health) {
        case EYXA_HEALTH_OK:       hs = L"Healthy";  break;
        case EYXA_HEALTH_DEGRADED: hs = L"Degraded"; break;
        case EYXA_HEALTH_ERROR:    hs = L"Error";    break;
        default:                   hs = L"Starting"; break;
    }

    /* Module alive list */
    WCHAR mods[256] = L"";
    struct { DWORD flag; const WCHAR *name; } ml[] = {
        { EYXA_MOD_SYSMON,  L"Sysmon"    },
        { EYXA_MOD_AMSI,    L"AMSI"      },
        { EYXA_MOD_CHANNEL, L"Channel"   },
        { EYXA_MOD_SENDER,  L"Sender"    },
        { EYXA_MOD_WS,      L"WebSocket" },
        { EYXA_MOD_DNS,     L"DNS"       },
        { EYXA_MOD_TAMPER,  L"Tamper"    },
    };
    for (int i = 0; i < 7; i++) {
        wcsncat_s(mods, ARRAYSIZE(mods),
                  (s.modules_alive & ml[i].flag) ? L"[OK] " : L"[--] ", _TRUNCATE);
        wcsncat_s(mods, ARRAYSIZE(mods), ml[i].name, _TRUNCATE);
        wcsncat_s(mods, ARRAYSIZE(mods), L"\n", _TRUNCATE);
    }

    _snwprintf_s(msg, ARRAYSIZE(msg), _TRUNCATE,
        L"Status:        %ls\n"
        L"Uptime:        %lld seconds\n"
        L"Events total:  %lld\n"
        L"Events sent:   %lld\n\n"
        L"Modules:\n%ls",
        hs, s.uptime_seconds, s.events_total, s.events_sent, mods);

    MessageBoxW(NULL, msg, L"Eyxa EDR - Agent Status", MB_OK | MB_ICONINFORMATION);
}

/* ── Right-click context menu ────────────────────────────────────────── */
static void ShowContextMenu(HWND hwnd)
{
    POINT pt;
    HMENU menu;
    EYXA_SHARED_STATUS s  = {0};
    BOOL  have_status = ReadStatus(&s);

    /* Required before TrackPopupMenu.
     * Source: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-trackpopupmenu */
    SetForegroundWindow(hwnd);
    GetCursorPos(&pt);

    menu = CreatePopupMenu();
    if (!menu) return;

    /* Header: prefer live read, fall back to last known health to avoid
     * showing "No signal" on a transient seqlock race. */
    {
        WCHAR hdr[128];
        WCHAR url[256], host[256];
        const WCHAR *hs = NULL;
        EYXA_HEALTH display_health = have_status ? s.health : g_last_health;

        switch (display_health) {
            case EYXA_HEALTH_OK:       hs = L"Healthy";       break;
            case EYXA_HEALTH_DEGRADED: hs = L"Degraded";      break;
            case EYXA_HEALTH_ERROR:    hs = L"Error";         break;
            case EYXA_HEALTH_STARTING: hs = L"Connecting..."; break;
            default:                   hs = L"Unknown";       break;
        }
        _snwprintf_s(hdr, ARRAYSIZE(hdr), _TRUNCATE, L"Eyxa EDR  -  %ls", hs);
        AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, hdr);

        /* Show current server IP as a grayed info line */
        GetBackendUrl(url, ARRAYSIZE(url));
        UrlToHost(url, host, ARRAYSIZE(host));
        _snwprintf_s(hdr, ARRAYSIZE(hdr), _TRUNCATE, L"Server: %ls", host);
        AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, hdr);
        
        BOOL is_offline = (s.modules_alive & EYXA_MOD_WS) == 0;
        if (display_health == EYXA_HEALTH_OK) {
            if (is_offline)
                _snwprintf_s(hdr, ARRAYSIZE(hdr), _TRUNCATE, L"Status: \xD83D\xDD34 Offline");
            else
                _snwprintf_s(hdr, ARRAYSIZE(hdr), _TRUNCATE, L"Status: \xD83D\xDFE2 Connected");
        } else {
            _snwprintf_s(hdr, ARRAYSIZE(hdr), _TRUNCATE, L"Status: \xD83D\xDD34 Local Error");
        }
        AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, hdr);

        _snwprintf_s(hdr, ARRAYSIZE(hdr), _TRUNCATE, L"Events Sent: %lld", s.events_sent);
        AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, hdr);

        /* Show enroll token (truncated) */
        WCHAR tok[64];
        GetEnrollToken(tok, ARRAYSIZE(tok));
        if (wcslen(tok) > 20) tok[20] = L'\0';  /* truncate for display */
        _snwprintf_s(hdr, ARRAYSIZE(hdr), _TRUNCATE, L"Token: %ls...", tok);
        AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, hdr);
    }

    AppendMenuW(menu, MF_SEPARATOR,  0,                   NULL);
    AppendMenuW(menu, MF_STRING,     IDM_OPEN_DASHBOARD,  L"Open Dashboard");
    AppendMenuW(menu, MF_STRING,     IDM_VIEW_STATUS,     L"View Agent Status");
    AppendMenuW(menu, MF_STRING,     IDM_CHANGE_SERVER,   L"Change Server IP...");
    AppendMenuW(menu, MF_SEPARATOR,  0,                   NULL);
    AppendMenuW(menu, MF_STRING,     IDM_RESTART_AGENT,   L"Restart Agent Service");
    AppendMenuW(menu, MF_STRING,     IDM_STOP_AGENT,      L"Stop Agent Service");
    AppendMenuW(menu, MF_STRING,     IDM_CONSOLE_MODE,    L"Run in Console Mode");
    AppendMenuW(menu, MF_SEPARATOR,  0,                   NULL);
    AppendMenuW(menu, MF_STRING,     IDM_EXIT,            L"Exit");

    TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
    PostMessageW(hwnd, WM_NULL, 0, 0);
    DestroyMenu(menu);
}

/* ── Watchdog: check service, restart if stopped ─────────────────────
 * Source: https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatus
 * Source: https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicea */
static void WatchdogTick(void)
{
    SC_HANDLE      scm = NULL, svc = NULL;
    SERVICE_STATUS ss  = {0};
    BOOL           running = FALSE;
    DWORD          now;

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return;

    svc = OpenServiceW(scm, SVC_NAME, SERVICE_QUERY_STATUS | SERVICE_START);
    if (!svc) { CloseServiceHandle(scm); return; } /* access denied at medium integrity is OK */

    if (QueryServiceStatus(svc, &ss))
        running = (ss.dwCurrentState == SERVICE_RUNNING ||
                   ss.dwCurrentState == SERVICE_START_PENDING);

    if (!running) {
        if (g_user_stopped || g_restarting) {
            /* User deliberately stopped/restarting the service -- do not auto-restart. */
            if (!g_restarting)
                SetTrayIcon(EYXA_HEALTH_ERROR, FALSE, L"Eyxa EDR - Agent stopped by user.");
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return;
        }
        SetTrayIcon(EYXA_HEALTH_ERROR, FALSE, L"Eyxa EDR - Agent stopped! Restarting...");

        now = GetTickCount();
        if (g_last_restart_tick &&
            (now - g_last_restart_tick) > (RESTART_COOLDOWN_SEC * 1000U))
            g_restart_count = 0;

        if (g_restart_count < MAX_RESTARTS) {
            if (StartServiceW(svc, 0, NULL)) {
                g_restart_count++;
                g_last_restart_tick = now;
                Balloon(L"Eyxa EDR Restarted",
                        L"The Eyxa agent was stopped and has been restarted automatically.",
                        NIIF_WARNING);
            } else {
                Balloon(L"Eyxa EDR - Restart Failed",
                        L"The Eyxa agent could not be restarted. Check services.msc.",
                        NIIF_ERROR);
            }
        } else {
            Balloon(L"Eyxa EDR - Repeated Failures",
                    L"Eyxa agent has crashed multiple times. Manual intervention required.",
                    NIIF_ERROR);
        }
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

/* ── Poll shared memory and update tray ──────────────────────────────────
 * Source: https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shell_notifyiconw */
static void PollTick(void)
{
    EYXA_SHARED_STATUS s = {0};

    TryOpenSharedMem();

    if (!ReadStatus(&s)) {
        /* Transient seqlock read failure. Only show "connecting" if we have
         * never successfully read the status -- otherwise keep the last
         * known health to avoid flickering the icon on every failed poll. */
        if (g_last_health == EYXA_HEALTH_STARTING)
            SetTrayIcon(EYXA_HEALTH_STARTING, FALSE, L"Eyxa EDR - Connecting to agent...");
        return;
    }

    /* New alert? */
    if (s.last_alert[0] != L'\0' && wcscmp(s.last_alert, g_last_alert) != 0) {
        wcscpy_s(g_last_alert, ARRAYSIZE(g_last_alert), s.last_alert);
        Balloon(L"\u26a0 Eyxa Security Alert", s.last_alert, NIIF_ERROR);
    }

    /* First batch confirmed sent? Fire the startup notification exactly once. */
    if (!g_first_batch_notified && s.events_sent > 0) {
        g_first_batch_notified = TRUE;
        Balloon(L"Eyxa EDR - Agent Running",
                L"Agent started successfully and is protecting this device.",
                NIIF_INFO);
    }
    
    BOOL is_offline = (s.modules_alive & EYXA_MOD_WS) == 0;

    /* Handle server offline/online transitions */
    static BOOL first_poll = TRUE;
    if (first_poll) {
        g_was_offline = is_offline;
        first_poll = FALSE;
    } else if (g_first_batch_notified) {
        if (is_offline && !g_was_offline) {
            Balloon(L"Connection Lost", L"Connection to Eyxa Server Lost. Telemetry is being buffered locally.", NIIF_WARNING);
            g_was_offline = TRUE;
        } else if (!is_offline && g_was_offline) {
            Balloon(L"Connection Restored", L"Connection to Eyxa Server restored. Buffered events are being flushed.", NIIF_INFO);
            g_was_offline = FALSE;
        }
    }

    /* Health changed? Fire a balloon for non-OK transitions. */
    if (s.health != g_last_health) {
        WCHAR tip[128];
        switch (s.health) {
            case EYXA_HEALTH_DEGRADED:
                Balloon(L"Eyxa EDR \u2013 Agent Degraded",
                        L"One or more modules have stopped. Telemetry may be incomplete.",
                        NIIF_WARNING);
                break;
            case EYXA_HEALTH_ERROR:
                Balloon(L"Eyxa EDR \u2013 Agent Error",
                        L"The agent has encountered a critical error.",
                        NIIF_ERROR);
                break;
            default:
                break;
        }
        
        if (s.health == EYXA_HEALTH_OK && is_offline) {
            _snwprintf_s(tip, ARRAYSIZE(tip), _TRUNCATE,
                L"Eyxa EDR | \x25CF Server Offline (Buffering)");
        } else {
            _snwprintf_s(tip, ARRAYSIZE(tip), _TRUNCATE,
                L"Eyxa EDR | %lld events sent | %llds uptime",
                s.events_sent, s.uptime_seconds);
        }
        
        SetTrayIcon(s.health, is_offline, tip);
    } else if (s.health == EYXA_HEALTH_OK) {
        /* Health didn't change, but we must update tip for live events_sent and handle offline transitions */
        WCHAR tip[128];
        if (is_offline) {
            _snwprintf_s(tip, ARRAYSIZE(tip), _TRUNCATE, L"Eyxa EDR | \x25CF Server Offline (Buffering)");
        } else {
            _snwprintf_s(tip, ARRAYSIZE(tip), _TRUNCATE, L"Eyxa EDR | %lld events sent | %llds uptime", s.events_sent, s.uptime_seconds);
        }
        SetTrayIcon(s.health, is_offline, tip);
    }
}

/* ── Window procedure ────────────────────────────────────────────────── */
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    /* Re-add tray icon if Explorer restarts.
     * Source: https://learn.microsoft.com/en-us/windows/win32/shell/taskbar#taskbarcreated */
    if (g_taskbar_msg && msg == g_taskbar_msg) {
        g_nid.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
        Shell_NotifyIconW(NIM_ADD, &g_nid);
        g_nid.uVersion = NOTIFYICON_VERSION_4;
        Shell_NotifyIconW(NIM_SETVERSION, &g_nid);
        return 0;
    }

    switch (msg) {

    case WM_TRAYICON:
        switch (LOWORD(lp)) {
        case WM_RBUTTONUP:
        case WM_CONTEXTMENU:
            ShowContextMenu(hwnd);
            break;
        case WM_LBUTTONDBLCLK:
            OpenDashboard();
            break;
        case NIN_BALLOONUSERCLICK:
            OpenDashboard();
            break;
        }
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDM_OPEN_DASHBOARD:
            OpenDashboard();
            break;
        case IDM_VIEW_STATUS:
            ShowStatusBox();
            break;
        case IDM_RESTART_AGENT: {
            /* Set g_restarting so the watchdog doesn't fire "Restart Failed" during
             * the brief window when the service is stopped between net stop/start. */
            g_restarting           = TRUE;
            g_user_stopped         = FALSE;
            g_first_batch_notified = FALSE;
            SHELLEXECUTEINFOW sei  = {0};
            sei.cbSize  = sizeof(sei);
            sei.fMask   = SEE_MASK_NOCLOSEPROCESS;
            sei.lpVerb  = L"runas";
            sei.lpFile  = L"cmd.exe";
            sei.lpParameters = L"/c net stop EyxaEDR & net start EyxaEDR";
            sei.nShow   = SW_HIDE;
            if (ShellExecuteExW(&sei)) {
                /* Wait for the cmd to complete before clearing g_restarting */
                if (sei.hProcess) {
                    WaitForSingleObject(sei.hProcess, 30000);
                    CloseHandle(sei.hProcess);
                }
                g_restarting = FALSE;
                Balloon(L"Eyxa EDR", L"Agent service restarted.", NIIF_INFO);
            } else {
                g_restarting = FALSE;
                Balloon(L"Eyxa EDR - Restart Failed",
                        L"Could not restart the service. UAC was denied.",
                        NIIF_ERROR);
            }
            break;
        }
        case IDM_STOP_AGENT: {
            g_user_stopped = TRUE;  /* tell watchdog not to auto-restart */
            SHELLEXECUTEINFOW sei = {0};
            sei.cbSize       = sizeof(sei);
            sei.fMask        = SEE_MASK_NOCLOSEPROCESS;
            sei.lpVerb       = L"runas";
            sei.lpFile       = L"cmd.exe";
            sei.lpParameters = L"/c net stop EyxaEDR";
            sei.nShow        = SW_HIDE;
            if (ShellExecuteExW(&sei)) {
                /* Wait for net stop to finish before notifying */
                if (sei.hProcess) {
                    WaitForSingleObject(sei.hProcess, 15000);
                    CloseHandle(sei.hProcess);
                }
                Balloon(L"Eyxa EDR", L"Agent service stopped.", NIIF_WARNING);
            } else {
                g_user_stopped = FALSE; /* reset - stop didn't even launch */
                Balloon(L"Eyxa EDR - Stop Failed",
                        L"Could not stop the service. UAC was denied.",
                        NIIF_ERROR);
            }
            break;
        }
        case IDM_CHANGE_SERVER:
            ChangeServerIp();
            break;
        case IDM_CONSOLE_MODE: {
            /* Stop the service and launch eyxa.exe directly in an elevated
             * cmd window -- it detects no SCM connection and falls back to
             * interactive/console mode with a live dashboard.
             * Source: https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecutew */
            g_user_stopped = TRUE;
            g_first_batch_notified = FALSE;
            SHELLEXECUTEINFOW sei = {0};
            sei.cbSize       = sizeof(sei);
            sei.fMask        = SEE_MASK_NOCLOSEPROCESS;
            sei.lpVerb       = L"runas";
            sei.lpFile       = L"cmd.exe";
            sei.lpParameters = L"/k net stop EyxaEDR & \"C:\\Program Files\\Eyxa\\eyxa.exe\"";
            sei.nShow        = SW_SHOW;
            if (!ShellExecuteExW(&sei)) {
                g_user_stopped = FALSE;
                Balloon(L"Eyxa EDR - Console Mode Failed",
                        L"Could not launch eyxa.exe. UAC was denied.", NIIF_ERROR);
            } else {
                if (sei.hProcess) CloseHandle(sei.hProcess);
            }
            break;
        }
        case IDM_EXIT:
            DestroyWindow(hwnd);
            break;
        }
        return 0;

    case WM_TIMER:
        /* Wrap timer callbacks: an unhandled exception here would kill the process */
        __try {
            if (wp == WATCHDOG_TIMER_ID) WatchdogTick();
            if (wp == POLL_TIMER_ID)     PollTick();
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            Log(L"WM_TIMER exception: timer=%llu code=0x%08lx",
                (unsigned long long)wp, GetExceptionCode());
        }
        return 0;

    case WM_DESTROY:
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
        KillTimer(hwnd, WATCHDOG_TIMER_ID);
        KillTimer(hwnd, POLL_TIMER_ID);
        if (g_shm)     UnmapViewOfFile(g_shm);
        if (g_shm_map) CloseHandle(g_shm_map);
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wp, lp);
}

/* ── WinMain ─────────────────────────────────────────────────────────── */
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, LPWSTR lpCmd, int nShow)
{
    (void)hPrev; (void)lpCmd; (void)nShow;
    MSG  msg;
    BOOL ok;

    Log(L"=== Terminator starting ===");

    /* Single-instance guard per user session.
     * Source: https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createmutexw */
    g_mutex = CreateMutexW(NULL, TRUE, INSTANCE_MUTEX);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        Log(L"Already running -- exiting.");
        CloseHandle(g_mutex);
        return 0;
    }
    Log(L"Mutex acquired.");

    /* Message-only window for tray callbacks.
     * Source: https://learn.microsoft.com/en-us/windows/win32/winmsg/window-features#message-only-windows */
    WNDCLASSEXW wc = {0};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = WNDCLASS_NAME;
    if (!RegisterClassExW(&wc)) {
        Log(L"RegisterClassExW failed: %lu", GetLastError());
        return 1;
    }

    g_hwnd = CreateWindowExW(0, WNDCLASS_NAME, L"Eyxa Terminator",
                              0, 0, 0, 0, 0, HWND_MESSAGE, NULL, hInst, NULL);
    if (!g_hwnd) {
        Log(L"CreateWindowExW failed: %lu", GetLastError());
        return 1;
    }
    Log(L"Window created: hwnd=%p", (void *)g_hwnd);

    /* Register TaskbarCreated and allow it through UIPI (needed when elevated).
     * Source: https://learn.microsoft.com/en-us/windows/win32/shell/taskbar#taskbarcreated
     * Source: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-changewindowmessagefilterex */
    g_taskbar_msg = RegisterWindowMessageW(L"TaskbarCreated");
    if (g_taskbar_msg)
        ChangeWindowMessageFilterEx(g_hwnd, g_taskbar_msg, MSGFLT_ALLOW, NULL);

    /* Add tray icon.
     * Source: https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shell_notifyiconw */
    g_nid.cbSize           = sizeof(g_nid);
    g_nid.hWnd             = g_hwnd;
    g_nid.uID              = TRAY_UID;
    g_nid.uFlags           = NIF_ICON | NIF_TIP | NIF_MESSAGE;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon            = HealthIcon(EYXA_HEALTH_STARTING);
    wcscpy_s(g_nid.szTip, ARRAYSIZE(g_nid.szTip), L"Eyxa EDR - Starting...");

    ok = Shell_NotifyIconW(NIM_ADD, &g_nid);
    Log(L"NIM_ADD: %ls (err=%lu)", ok ? L"OK" : L"FAILED", GetLastError());

    g_nid.uVersion = NOTIFYICON_VERSION_4;
    Shell_NotifyIconW(NIM_SETVERSION, &g_nid);

    /* Connect to shared memory */
    TryOpenSharedMem();
    Log(L"Shared memory: %ls", g_shm ? L"connected" : L"not available yet");

    /* Start timers */
    SetTimer(g_hwnd, WATCHDOG_TIMER_ID, WATCHDOG_INTERVAL_MS, NULL);
    SetTimer(g_hwnd, POLL_TIMER_ID,     POLL_INTERVAL_MS,     NULL);

    /* Run initial ticks to populate icon state immediately */
    __try {
        WatchdogTick();
        PollTick();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Log(L"Exception in initial ticks: 0x%08lx", GetExceptionCode());
    }

    Log(L"Entering message loop.");

    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    if (g_mutex) {
        ReleaseMutex(g_mutex);
        CloseHandle(g_mutex);
    }
    Log(L"=== Terminator exited cleanly ===");
    return 0;
}
