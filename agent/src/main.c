/*
 * Eyxa agent -- production entry point (dual-mode: service + console).
 *
 * When launched by the Windows Service Control Manager (SCM):
 *   - Calls StartServiceCtrlDispatcherW → runs as a proper Windows service.
 *   - Logs to C:\ProgramData\Eyxa\eyxa.log (no console available as SYSTEM).
 *   - Responds to SERVICE_CONTROL_STOP / SERVICE_CONTROL_SHUTDOWN.
 *   - Running as LocalSystem grants SeSecurityPrivilege → Security log 3/3.
 *
 * When launched interactively (console/debug mode):
 *   - StartServiceCtrlDispatcherW returns FALSE with
 *     ERROR_FAILED_SERVICE_CONTROLLER_CONNECT.
 *   - Falls back to direct console execution (Ctrl+C to stop).
 *   - Logs to stdout as before.
 *
 * Unity-build: include all modules in one translation unit.
 * Build command (from x64 Native Tools Command Prompt):
 *
 *   cl.exe /nologo /W3 /O2 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0602 ^
 *       /Fo"c:\product\garbage\\" ^
 *       "c:\product\eyxa\agent\src\main.c" ^
 *       /Fe:"c:\product\eyxa\installer\eyxa.exe" ^
 *       /link advapi32.lib ole32.lib shell32.lib wevtapi.lib ^
 *              winhttp.lib kernel32.lib ws2_32.lib tdh.lib aclui.lib
 *
 * Build terminator.exe separately:
 *   cl.exe /nologo /W3 /O2 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0602 ^
 *       /Fo"c:\product\garbage\\" ^
 *       "c:\product\eyxa\agent\src\tray.c" ^
 *       /Fe:"c:\product\eyxa\installer\terminator.exe" ^
 *       /link /SUBSYSTEM:WINDOWS advapi32.lib shell32.lib user32.lib kernel32.lib
 *
 * Include chain (all protected by #ifndef guards):
 *   main.c
 *     sender.c         -> buffer.c, enrollment.c
 *     sysmon_reader.c
 *     amsi_reader.c
 *     normalizer.c     -> EyxaNormalizeSysmonXml, EyxaNormalizeAmsiEvent
 *     channel_reader.c -> generic EvtSubscribe reader (eyxa.xml-driven)
 *     responder.c      -> ws_client.c -> enrollment.c (guard: no-op)
 *     dns_reader.c     -> ETW DNS-Client telemetry (A7)
 *     tamper_watcher.c -> ReadDirectoryChangesW watcher (A9)
 */

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0602
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "sender.c"          /* pulls in buffer.c + enrollment.c              */
#include "sysmon_reader.c"   /* defines EYXA_SYSMON_READER, EYXA_EVENT_SINK   */
#include "amsi_reader.c"
#include "normalizer.c"      /* EyxaNormalizeSysmonXml, EyxaNormalizeAmsiEvent */
#include "channel_reader.c"  /* generic EvtSubscribe reader for eyxa.xml       */
#include "responder.c"       /* pulls in ws_client.c                           */
#include "dns_reader.c"      /* ETW DNS-Client telemetry (A7)                  */
#include "tamper_watcher.c" /* ReadDirectoryChangesW watcher (A9)              */
#include "shared_status.h"   /* named shared-memory IPC to terminator.exe      */

/* ── Module globals ─────────────────────────────────────────────────── */
static EYXA_ENROLLMENT     g_enroll;
static EYXA_BUFFER         g_buf;
static EYXA_SENDER         g_sender;
static EYXA_SYSMON_READER  g_sysmon;
static EYXA_AMSI_READER    g_amsi;
static EYXA_CHANNEL_READER g_channel;
static EYXA_WS_CLIENT      g_ws;
static EYXA_DNS_READER     g_dns;
static EYXA_TAMPER_WATCHER g_tamper;

/* ── Shared memory status block (written by heartbeat thread) ─────── */
static HANDLE              g_status_map_handle = NULL;
static EYXA_SHARED_STATUS *g_shared_status     = NULL;
static LONGLONG            g_events_total      = 0;
static LONGLONG            g_events_sent       = 0;
static LONGLONG            g_start_tick        = 0;
static WCHAR               g_last_alert_ipc[128] = {0};

static volatile LONG g_stopping = 0;

/* ── Console output lock (console mode only) ─────────────────────────
 * Serialises Log() writes and the dashboard header redraws so they
 * never interleave on stdout. */
static CRITICAL_SECTION g_console_lock;
static BOOL             g_console_lock_init = FALSE;

/* ── Persistent total counter file ──────────────────────────────────── */
#define EYXA_TOTAL_FILE L"C:\\ProgramData\\Eyxa\\eyxa-total.bin"

/* ── Service mode globals ────────────────────────────────────────────── */
static BOOL                  g_service_mode = FALSE;
static SERVICE_STATUS_HANDLE g_svc_handle   = NULL;
static SERVICE_STATUS        g_svc_status   = {0};

#define EYXA_SVC_NAME  L"EyxaEDR"
#define HEADER_H       11   /* rows reserved for the fixed header (rows 0..10) */

/* ── Persist/load cumulative events_total across sessions (Option A) ──
 * Written on clean shutdown; read back on startup and added to the
 * in-memory counter so the displayed total accumulates across reboots.
 * Source: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew */
static void LoadPersistedTotal(void)
{
    HANDLE h = CreateFileW(EYXA_TOTAL_FILE, GENERIC_READ, 0, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    LONGLONG val = 0; DWORD rd = 0;
    if (ReadFile(h, &val, sizeof(val), &rd, NULL) && rd == sizeof(val))
        InterlockedAdd64(&g_events_total, val);
    CloseHandle(h);
}
static void SavePersistedTotal(void)
{
    LONGLONG val = g_events_total;
    HANDLE h = CreateFileW(EYXA_TOTAL_FILE, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD wr = 0;
    WriteFile(h, &val, sizeof(val), &wr, NULL);
    CloseHandle(h);
}

/* ── Logging helper (console + service mode) ─────────────────────────
 * Console mode : plain scrolling stdout. g_console_lock serialises
 *                concurrent Log() calls from multiple module threads.
 * Service mode : appends to C:\ProgramData\Eyxa\eyxa.log.
 * Source: https://learn.microsoft.com/en-us/windows/win32/services/writing-a-service-main-function
 */
static void Log(const wchar_t *fmt, ...)
{
    wchar_t buf[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(buf, ARRAYSIZE(buf), _TRUNCATE, fmt, ap);
    va_end(ap);

    /* Always write to log file (both service and console modes). */
    FILE *f = NULL;
    CreateDirectoryW(L"C:\\Program" L"Data\\Eyxa", NULL);
    if (_wfopen_s(&f, L"C:\\Program" L"Data\\Eyxa\\eyxa.log", L"a, ccs=UTF-8") == 0 && f) {
        fwprintf(f, L"[eyxa] %ls\n", buf);
        fclose(f);
    }

    if (!g_service_mode) {
        if (g_console_lock_init) EnterCriticalSection(&g_console_lock);
        wprintf(L"[eyxa] %ls\r\n", buf);
        fflush(stdout);
        if (g_console_lock_init) LeaveCriticalSection(&g_console_lock);
    }
}

/* ── Sysmon event sink ───────────────────────────────────────────────
 * Called by sysmon_reader for every subscribed Sysmon event (all EIDs).
 * Normalises raw XML -> JSON including meta fields (EventID, Channel,
 * TimeCreated, source) so ingest.py can store them in the right columns.
 */
static BOOL WINAPI SysmonSink(const WCHAR *channel, const WCHAR *event_xml,
                               void *context)
{
    EYXA_BUFFER   *buf  = (EYXA_BUFFER *)context;
    EYXA_NORM_META meta;
    char           data_json[65536];  /* 64 KB for long CommandLine/CallTrace */
    char           final_json[65800];
    int            data_len, final_len;
    (void)channel;

    if (!EyxaNormalizeSysmonXml(event_xml, data_json, (DWORD)sizeof(data_json), &meta)) {
        Log(L"WARNING: SysmonSink dropped event - payload too large or malformed XML");
        return FALSE;
    }

    data_len = (int)strlen(data_json);
    if (data_len < 2) return FALSE;  /* need at least {} */

    final_len = _snprintf_s(final_json, sizeof(final_json), _TRUNCATE,
        "{\"EventID\":%d,\"Channel\":\"%s\","
        "\"TimeCreated\":\"%s\",\"source\":\"sysmon\",%s",
        meta.event_id, meta.channel, meta.time_created,
        data_json + 1);   /* skip leading '{' */

    if (final_len <= 0) return FALSE;
    return EyxaBufferAppend(buf, (const BYTE *)final_json, (DWORD)final_len);
}

/* ── Channel event sink ───────────────────────────────────────────────
 * Called by channel_reader for every event from a non-Sysmon Windows
 * Event Log channel declared in eyxa.xml (Security, Defender, PowerShell).
 * source field is "winevent" to distinguish from Sysmon events.
 */
static BOOL WINAPI ChannelSink(const WCHAR *channel, const WCHAR *event_xml,
                                void *context)
{
    EYXA_BUFFER   *buf  = (EYXA_BUFFER *)context;
    EYXA_NORM_META meta;
    char           data_json[65536];
    char           final_json[65800];
    int            data_len, final_len;
    (void)channel;

    if (!EyxaNormalizeSysmonXml(event_xml, data_json, (DWORD)sizeof(data_json), &meta)) {
        Log(L"WARNING: ChannelSink dropped event - payload too large or malformed XML");
        return FALSE;
    }

    data_len = (int)strlen(data_json);
    if (data_len < 2) return FALSE;

    final_len = _snprintf_s(final_json, sizeof(final_json), _TRUNCATE,
        "{\"EventID\":%d,\"Channel\":\"%s\","
        "\"TimeCreated\":\"%s\",\"source\":\"winevent\",%s",
        meta.event_id, meta.channel, meta.time_created,
        data_json + 1);

    if (final_len <= 0) return FALSE;
    return EyxaBufferAppend(buf, (const BYTE *)final_json, (DWORD)final_len);
}

/* ── AMSI event sink ──────────────────────────────────────────────── */
static BOOL WINAPI AmsiSink(const EYXA_AMSI_EVENT *ev, void *context)
{
    EYXA_BUFFER   *buf  = (EYXA_BUFFER *)context;
    EYXA_NORM_META meta;
    char           data_json[65536];
    char           final_json[65800];
    int            data_len, final_len;

    if (!EyxaNormalizeAmsiEvent(ev, data_json, (DWORD)sizeof(data_json), &meta)) {
        Log(L"WARNING: AmsiSink dropped event - payload too large or malformed");
        return FALSE;
    }

    data_len = (int)strlen(data_json);
    if (data_len < 2) return FALSE;

    final_len = _snprintf_s(final_json, sizeof(final_json), _TRUNCATE,
        "{\"EventID\":%d,\"Channel\":\"%s\","
        "\"TimeCreated\":\"%s\",\"source\":\"amsi\",%s",
        meta.event_id, meta.channel, meta.time_created,
        data_json + 1);

    if (final_len <= 0) return FALSE;
    return EyxaBufferAppend(buf, (const BYTE *)final_json, (DWORD)final_len);
}

/* ── DNS event sink ──────────────────────────────────────────────── */
static BOOL WINAPI DnsSink(const char *json, void *context)
{
    EYXA_BUFFER *buf = (EYXA_BUFFER *)context;
    InterlockedIncrement64(&g_events_total);
    return EyxaBufferAppend(buf, (const BYTE *)json, (DWORD)strlen(json));
}

/* ── Tamper event sink ───────────────────────────────────────────── */
static BOOL WINAPI TamperSink(const char *json, void *context)
{
    EYXA_BUFFER *buf = (EYXA_BUFFER *)context;
    Log(L"TAMPER DETECTED: %hs", json);
    InterlockedIncrement64(&g_events_total);
    return EyxaBufferAppend(buf, (const BYTE *)json, (DWORD)strlen(json));
}

/* ── Sender status callback ─────────────────────────────────────────── */
static void SenderEventCb(BOOL success, DWORD http_status,
                           DWORD records_sent, void *context)
{
    (void)context;
    if (success) {
        InterlockedAdd64(&g_events_sent, (LONGLONG)records_sent);
        Log(L"sender: flushed %lu records (HTTP %lu)", records_sent, http_status);
    } else
        Log(L"sender: send failed (HTTP %lu)", http_status);
}

/* ── Heartbeat + shared memory writer thread (A3) ──────────────────
 * Writes agent health to the named shared memory block every 30 seconds
 * so terminator.exe can read it and update the tray icon.
 * Source: https://learn.microsoft.com/en-us/windows/win32/memory/creating-named-shared-memory */
static DWORD WINAPI HeartbeatThread(LPVOID param)
{
    (void)param;
    while (!InterlockedCompareExchange(&g_stopping, 0, 0)) {
        Sleep(30000);
        if (InterlockedCompareExchange(&g_stopping, 0, 0)) break;

        LONGLONG uptime = (GetTickCount64() - (ULONGLONG)g_start_tick) / 1000ULL;
        DWORD mods = 0;
        if (!EyxaSysmonReaderFailed(&g_sysmon, NULL)) {
            mods |= EYXA_MOD_SYSMON;
        } else {
            Log(L"[heartbeat] Sysmon reader failed (err=%lu). Auto-restarting...", g_sysmon.last_error);
            EyxaSysmonReaderStop(&g_sysmon);
            if (EyxaSysmonReaderStart(&g_sysmon, SysmonSink, &g_buf)) {
                mods |= EYXA_MOD_SYSMON;
            }
        }
        if (!EyxaAmsiReaderFailed(&g_amsi, NULL))      mods |= EYXA_MOD_AMSI;
        if (EyxaChannelReaderStarted(&g_channel) > 0) mods |= EYXA_MOD_CHANNEL;
        if (!EyxaWsClientFailed(&g_ws, NULL))         mods |= EYXA_MOD_WS;
        if (!EyxaDnsReaderFailed(&g_dns))             mods |= EYXA_MOD_DNS;
        mods |= EYXA_MOD_SENDER;  /* sender is always alive if we reach here */
        mods |= EYXA_MOD_TAMPER;  /* tamper watcher always alive */

        EYXA_HEALTH health;
        DWORD dead = (~mods) & (EYXA_MOD_SYSMON | EYXA_MOD_AMSI | EYXA_MOD_SENDER);
        if (dead) health = EYXA_HEALTH_DEGRADED;
        else      health = EYXA_HEALTH_OK;

        Log(L"[heartbeat] health=%d mods=0x%lx events_total=%lld events_sent=%lld uptime=%llds",
            (int)health, (unsigned long)mods,
            g_events_total, g_events_sent, uptime);

        if (g_shared_status) {
            EyxaStatusBeginWrite(g_shared_status);
            g_shared_status->health        = health;
            g_shared_status->modules_alive = mods;
            g_shared_status->events_total  = g_events_total;
            g_shared_status->events_sent   = g_events_sent;
            g_shared_status->uptime_seconds = uptime;
            /* Copy last alert if changed (set by responder.c alert delivery) */
            if (g_last_alert_ipc[0])
                wcsncpy_s(g_shared_status->last_alert,
                          ARRAYSIZE(g_shared_status->last_alert),
                          g_last_alert_ipc, _TRUNCATE);
            EyxaStatusEndWrite(g_shared_status);
        }
    }
    return 0;
}

/* ── Inventory re-diff thread (A8) ─────────────────────────────────
 * Every 24 hours re-collects hardware inventory and sends a JSON event
 * so the backend can diff it against the stored baseline.
 * High-value for detecting: new NICs (rogue USB adapter), new disks (USB). */
static DWORD WINAPI InventoryDiffThread(LPVOID param)
{
    (void)param;
    /* Wait 24h before first re-check. The initial inventory is sent
     * by the WebSocket thread immediately on connect. */
    DWORD wait_ms = 86400000UL; /* 24 hours */
    while (!InterlockedCompareExchange(&g_stopping, 0, 0)) {
        /* Sleep in 30-second slices so we can respond to stop quickly */
        for (DWORD slept = 0; slept < wait_ms; slept += 30000) {
            Sleep(30000);
            if (InterlockedCompareExchange(&g_stopping, 0, 0)) return 0;
        }
        char inv_msg[8192];
        if (EyxaHardwareInventory(inv_msg, sizeof(inv_msg))) {
            Log(L"[inventory] re-sending 24h hardware inventory diff");
            EyxaBufferAppend(&g_buf, (const BYTE *)inv_msg, (DWORD)strlen(inv_msg));
        }
    }
    return 0;
}

/* Console dashboard removed: the fixed-header approach caused ghost rows
 * and garbled log lines when the header redraw thread and Log() collided.
 * Health and module status are displayed by the tray icon (terminator.exe)
 * and the web dashboard. In console mode, output is plain scrolling log. */

/* Write one header row at window-relative position, erasing to EOL.
 * win_top = csbi.srWindow.Top so header always stays at the visible top.
 * Source: https://learn.microsoft.com/en-us/windows/console/setconsolecursorposition */
static void HRow(HANDLE hOut, SHORT win_top, SHORT row, const wchar_t *fmt, ...)
{
    COORD pos = {0, (SHORT)(win_top + row)};
    SetConsoleCursorPosition(hOut, pos);
    wchar_t line[256];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(line, ARRAYSIZE(line), _TRUNCATE, fmt, ap);
    va_end(ap);
    wprintf(L"%ls\x1b[K", line);  /* \x1b[K = erase to end of line */
}

static void DrawHeader(HANDLE hOut)
{
    /* Get current visible window top so header is always at screen top */
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (!GetConsoleScreenBufferInfo(hOut, &csbi)) return;
    SHORT wt = csbi.srWindow.Top;

    LONGLONG uptime = (GetTickCount64() - (ULONGLONG)g_start_tick) / 1000ULL;
    LONGLONG hrs    = uptime / 3600;
    LONGLONG mins   = (uptime % 3600) / 60;
    LONGLONG secs   = uptime % 60;

    DWORD live = 0;
    if (!EyxaSysmonReaderFailed(&g_sysmon, NULL)) live |= EYXA_MOD_SYSMON;
    if (!EyxaAmsiReaderFailed(&g_amsi, NULL))     live |= EYXA_MOD_AMSI;
    if (EyxaChannelReaderStarted(&g_channel) > 0) live |= EYXA_MOD_CHANNEL;
    live |= EYXA_MOD_SENDER;
    if (!EyxaWsClientFailed(&g_ws, NULL))         live |= EYXA_MOD_WS;
    if (!EyxaDnsReaderFailed(&g_dns))             live |= EYXA_MOD_DNS;
    live |= EYXA_MOD_TAMPER;

    BOOL healthy = ((~live) & (EYXA_MOD_SYSMON | EYXA_MOD_AMSI | EYXA_MOD_SENDER)) == 0;

    WCHAR tok_short[24] = L"(not enrolled)";
    if (g_enroll.agent_token[0]) {
        wcsncpy_s(tok_short, ARRAYSIZE(tok_short), g_enroll.agent_token, 20);
        wcsncat_s(tok_short, ARRAYSIZE(tok_short), L"...", _TRUNCATE);
    }

    static const struct { DWORD flag; const wchar_t *name; } ml[] = {
        { EYXA_MOD_SYSMON,  L"Sysmon"  }, { EYXA_MOD_AMSI,    L"AMSI"    },
        { EYXA_MOD_CHANNEL, L"Channel" }, { EYXA_MOD_SENDER,  L"Sender"  },
        { EYXA_MOD_WS,      L"WS"      }, { EYXA_MOD_DNS,     L"DNS ETW" },
        { EYXA_MOD_TAMPER,  L"Tamper"  },
    };

    /* Build two module rows (4 + 3) */
    WCHAR row1[120] = L"", row2[120] = L"";
    for (int i = 0; i < 4; i++) {
        BOOL a = (live & ml[i].flag) != 0;
        WCHAR seg[32];
        _snwprintf_s(seg, ARRAYSIZE(seg), _TRUNCATE,
                     L"%ls[%ls] %ls\x1b[0m  ",
                     a ? L"\x1b[92m" : L"\x1b[91m", a ? L"OK" : L"!!",
                     ml[i].name);
        wcsncat_s(row1, ARRAYSIZE(row1), seg, _TRUNCATE);
    }
    for (int i = 4; i < 7; i++) {
        BOOL a = (live & ml[i].flag) != 0;
        WCHAR seg[32];
        _snwprintf_s(seg, ARRAYSIZE(seg), _TRUNCATE,
                     L"%ls[%ls] %ls\x1b[0m  ",
                     a ? L"\x1b[92m" : L"\x1b[91m", a ? L"OK" : L"!!",
                     ml[i].name);
        wcsncat_s(row2, ARRAYSIZE(row2), seg, _TRUNCATE);
    }

    /* Draw header rows using Win32 cursor positioning, offset by srWindow.Top */
    /* Source: https://learn.microsoft.com/en-us/windows/console/setconsolecursorposition */
    HRow(hOut, wt, 0,  L"\x1b[96m\x1b[1m  EYXA EDR\x1b[0m\x1b[90m  --- Console Mode --------------------------\x1b[0m");
    HRow(hOut, wt, 1,  L"  %ls%-10ls\x1b[0m  \x1b[90mUptime: %lld:%02lld:%02lld\x1b[0m",
         healthy ? L"\x1b[92m* HEALTHY  " : L"\x1b[93m* DEGRADED ",
         L"", hrs, mins, secs);
    HRow(hOut, wt, 2,  L"  \x1b[90mServer : \x1b[0m%ls", g_enroll.backend_url);
    HRow(hOut, wt, 3,  L"  \x1b[90mToken  : \x1b[0m%ls", tok_short);
    HRow(hOut, wt, 4,  L"  \x1b[90mHost   : \x1b[0m%ls", g_enroll.hostname);
    HRow(hOut, wt, 5,  L"  \x1b[90mEvents : total=\x1b[0m%lld  \x1b[90msent=\x1b[0m%lld",
         g_events_total, g_events_sent);
    HRow(hOut, wt, 6,  L"  \x1b[90mMods   : \x1b[0m%ls", row1);
    HRow(hOut, wt, 7,  L"           %ls", row2);
    HRow(hOut, wt, 8,  L"\x1b[90m  ------------------------------------------  Live log:\x1b[0m");
    HRow(hOut, wt, 9,  L"");
    HRow(hOut, wt, 10, L"");
    fflush(stdout);
}

static DWORD WINAPI ConsoleDashboardThread(LPVOID param)
{
    (void)param;

    /* Enable VT/ANSI colour processing on stdout.
     * Source: https://learn.microsoft.com/en-us/windows/console/setconsolemode */
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD  mode = 0;
    GetConsoleMode(hOut, &mode);
    SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    /* Clear screen and park cursor at the log area start.
     * Source: https://learn.microsoft.com/en-us/windows/console/setconsolecursorposition */
    EnterCriticalSection(&g_console_lock);
    wprintf(L"\x1b[2J");      /* clear screen */
    COORD log_start = {0, HEADER_H};
    SetConsoleCursorPosition(hOut, log_start);
    fflush(stdout);
    LeaveCriticalSection(&g_console_lock);

    /* Wait for all modules to start before first draw */
    Sleep(2000);

    while (!InterlockedCompareExchange(&g_stopping, 0, 0)) {
        EnterCriticalSection(&g_console_lock);

        /* Save log cursor, draw header at window-top + 0..HEADER_H-1, restore */
        CONSOLE_SCREEN_BUFFER_INFO ci;
        GetConsoleScreenBufferInfo(hOut, &ci);
        SHORT min_row = ci.srWindow.Top + HEADER_H;
        COORD saved = ci.dwCursorPosition;
        if (saved.Y < min_row) { saved.Y = min_row; saved.X = 0; }

        DrawHeader(hOut);

        SetConsoleCursorPosition(hOut, saved);
        fflush(stdout);
        LeaveCriticalSection(&g_console_lock);
        Sleep(1000);
    }

    /* On exit: move cursor below header */
    EnterCriticalSection(&g_console_lock);
    CONSOLE_SCREEN_BUFFER_INFO ci2;
    GetConsoleScreenBufferInfo(hOut, &ci2);
    SHORT exit_min = ci2.srWindow.Top + HEADER_H;
    if (ci2.dwCursorPosition.Y < exit_min) {
        COORD c = {0, exit_min};
        SetConsoleCursorPosition(hOut, c);
    }
    LeaveCriticalSection(&g_console_lock);
    return 0;
}

/* ── Ctrl+C handler (console mode only) ─────────────────────────────── */
static BOOL WINAPI CtrlHandler(DWORD ctrl_type)
{
    if (ctrl_type == CTRL_C_EVENT     || ctrl_type == CTRL_BREAK_EVENT ||
        ctrl_type == CTRL_CLOSE_EVENT || ctrl_type == CTRL_SHUTDOWN_EVENT) {
        InterlockedExchange(&g_stopping, 1);
        return TRUE;
    }
    return FALSE;
}

/* ── Core agent logic (shared: service mode + console mode) ──────────
 * Starts all 7 modules in dependency order, waits for stop signal,
 * then shuts down in reverse order.
 */
static void RunAgent(void)
{
    /* ── Startup tick ──────────────────────────────────────────────── */
    BOOL ok;
    g_start_tick = (LONGLONG)GetTickCount64();

    /* ── Load persisted cumulative events_total from previous sessions ─ */
    LoadPersistedTotal();

    /* ── Init console lock (console mode only) ──────────────────────── */
    if (!g_service_mode) {
        InitializeCriticalSection(&g_console_lock);
        g_console_lock_init = TRUE;
    }

    /* ── Create shared memory block for terminator.exe ─────────────
     * Security: SYSTEM creates it, anyone in the local session can read.
     * Source: https://learn.microsoft.com/en-us/windows/win32/memory/creating-named-shared-memory */
    {
        SECURITY_DESCRIPTOR sd;
        SECURITY_ATTRIBUTES sa;
        InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE); /* NULL DACL = everyone read */
        sa.nLength              = sizeof(sa);
        sa.lpSecurityDescriptor = &sd;
        sa.bInheritHandle       = FALSE;
        g_status_map_handle = CreateFileMappingW(
            INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE,
            0, EYXA_STATUS_MAP_SIZE, EYXA_STATUS_MAP_NAME);
        if (g_status_map_handle) {
            g_shared_status = (EYXA_SHARED_STATUS *)MapViewOfFile(
                g_status_map_handle, FILE_MAP_ALL_ACCESS, 0, 0, EYXA_STATUS_MAP_SIZE);
            if (g_shared_status) {
                ZeroMemory(g_shared_status, EYXA_STATUS_MAP_SIZE);
                Log(L"Shared status memory: created (terminator.exe can now read).");
            }
        } else {
            Log(L"WARNING: could not create shared status memory (error %lu). Tray icon will show no data.",
                GetLastError());
        }
    }

    Log(L"[1/7] Enrollment ...");
    ZeroMemory(&g_enroll, sizeof(g_enroll));
    ok = EyxaEnrollmentInit(&g_enroll);
    if (!ok) {
        Log(L"FATAL: enrollment failed.");
        Log(L"       Set HKLM\\SOFTWARE\\Eyxa\\EnrollToken and BackendUrl.");
        return;
    }
    Log(L"[1/7] Enrolled. machine_id=%ls  host=%ls",
        g_enroll.machine_id, g_enroll.hostname);

    /* ── 2. Buffer ──────────────────────────────────────────────────── */
    Log(L"[2/7] Opening durable event buffer ...");
    ZeroMemory(&g_buf, sizeof(g_buf));
    ok = EyxaBufferOpen(&g_buf);
    if (!ok) {
        Log(L"FATAL: buffer open failed (service must run as SYSTEM or Administrator)");
        EyxaEnrollmentCleanup(&g_enroll);
        return;
    }
    Log(L"[2/7] Buffer open.");

    /* ── 3. Sender ──────────────────────────────────────────────────── */
    Log(L"[3/7] Starting HTTPS sender (30s interval) ...");
    ZeroMemory(&g_sender, sizeof(g_sender));
    ok = EyxaSenderStart(&g_sender, &g_buf, &g_enroll, SenderEventCb, NULL);
    if (!ok) {
        Log(L"FATAL: sender start failed");
        EyxaBufferClose(&g_buf);
        EyxaEnrollmentCleanup(&g_enroll);
        return;
    }
    Log(L"[3/7] Sender thread running.");

    /* ── 4. Sysmon reader ───────────────────────────────────────────── */
    Log(L"[4/9] Starting Sysmon reader (all EIDs, config-driven) ...");
    ZeroMemory(&g_sysmon, sizeof(g_sysmon));
    ok = EyxaSysmonReaderStart(&g_sysmon, SysmonSink, &g_buf);
    if (!ok)
        Log(L"WARNING: Sysmon reader failed - is Sysmon installed and running?");
    else if (g_sysmon.last_error == ERROR_EVT_QUERY_RESULT_STALE)
        Log(L"WARNING: [A1] Sysmon bookmark was stale (log rotated during offline period). "
            L"Coverage gap acknowledged. Resuming from newest event.");
    else
        Log(L"[4/9] Sysmon reader running.");

    /* ── 5. Channel reader (eyxa.xml) ───────────────────────────────── */
    {
        /* Enable SeSecurityPrivilege so EvtSubscribe can access the Security
         * Admin log (EID 1102/4698).  As SYSTEM, this privilege is always
         * present.  As interactive admin, AdjustTokenPrivileges enables it.
         * Source: https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants */
        HANDLE hToken;
        LUID   luid;
        TOKEN_PRIVILEGES tp;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            if (LookupPrivilegeValue(NULL, SE_SECURITY_NAME, &luid)) {
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Luid = luid;
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
            }
            CloseHandle(hToken);
        }
    }
    Log(L"[5/9] Starting channel reader (eyxa.xml) ...");
    ZeroMemory(&g_channel, sizeof(g_channel));
    ok = EyxaChannelReaderStart(&g_channel, ChannelSink, &g_buf, NULL);
    if (!ok) {
        Log(L"WARNING: channel reader failed - eyxa.xml missing or no channels subscribed.");
        Log(L"         Expected: eyxa.xml in same directory as eyxa.exe");
    } else {
        Log(L"[5/9] Channel reader: %lu/%lu subscriptions active.",
            (unsigned long)EyxaChannelReaderStarted(&g_channel),
            (unsigned long)g_channel.count);
        for (DWORD i = 0; i < g_channel.count; i++) {
            if (g_channel.entries[i].subscription == NULL) {
                Log(L"         -> FAILED: %ls (Error: %lu)",
                    g_channel.entries[i].channel, g_channel.entries[i].last_error);
            }
        }
    }

    /* ── 6. AMSI reader ─────────────────────────────────────────────── */
    Log(L"[6/9] Starting AMSI ETW reader (EID 1101) ...");
    ZeroMemory(&g_amsi, sizeof(g_amsi));
    ok = EyxaAmsiReaderStart(&g_amsi, AmsiSink, &g_buf);
    if (!ok)
        Log(L"WARNING: AMSI reader failed - ETW session requires SYSTEM or admin");
    else
        Log(L"[6/9] AMSI reader running.");

    /* ── 7. WebSocket + responder ───────────────────────────────────── */
    Log(L"[7/9] Starting WebSocket client ...");
    ZeroMemory(&g_ws, sizeof(g_ws));
    ok = EyxaWsClientStart(&g_ws, &g_enroll, EyxaCommandCallback, &g_ws);
    if (!ok)
        Log(L"WARNING: WebSocket failed - response actions unavailable");
    else
        Log(L"[7/9] WebSocket connected. Dashboard response actions active.");

    /* ── 8. DNS ETW reader ──────────────────────────────────────────── */
    Log(L"[8/9] Starting DNS ETW reader (Microsoft-Windows-DNS-Client) ...");
    ZeroMemory(&g_dns, sizeof(g_dns));
    ok = EyxaDnsReaderStart(&g_dns, DnsSink, &g_buf);
    if (!ok)
        Log(L"WARNING: DNS reader failed - DNS telemetry unavailable.");
    else
        Log(L"[8/9] DNS reader running.");

    /* ── 9. Tamper watcher ──────────────────────────────────────────── */
    Log(L"[9/9] Starting tamper watcher (C:\\ProgramData\\Eyxa) ...");
    ZeroMemory(&g_tamper, sizeof(g_tamper));
    ok = EyxaTamperWatcherStart(&g_tamper, TamperSink, &g_buf);
    if (!ok)
        Log(L"WARNING: Tamper watcher failed - file monitoring unavailable.");
    else
        Log(L"[9/9] Tamper watcher running.");

    /* ── Heartbeat thread (A3) ──────────────────────────────────────── */
    HANDLE h_heartbeat = CreateThread(NULL, 0, HeartbeatThread, NULL, 0, NULL);
    if (!h_heartbeat) Log(L"WARNING: heartbeat thread failed to start.");

    /* ── Inventory diff thread (A8) ─────────────────────────────────── */
    HANDLE h_inventory = CreateThread(NULL, 0, InventoryDiffThread, NULL, 0, NULL);
    if (!h_inventory) Log(L"WARNING: inventory diff thread failed to start.");

    Log(g_service_mode ? L"All 9 modules running (service mode). Log: C:\\Program" L"Data\\Eyxa\\eyxa.log"
                       : L"All 9 modules running. Press Ctrl+C to stop.");

    /* ── Main wait loop ─────────────────────────────────────────────── */
    while (!g_stopping)
        Sleep(500);

    /* ── Graceful shutdown (reverse order) ──────────────────────────── */
    Log(L"Shutting down ...");
    /* Signal helper threads first */
    if (h_heartbeat) { WaitForSingleObject(h_heartbeat, 5000); CloseHandle(h_heartbeat); }
    if (h_inventory) { WaitForSingleObject(h_inventory, 5000); CloseHandle(h_inventory); }
    EyxaTamperWatcherStop(&g_tamper);
    EyxaDnsReaderStop(&g_dns);
    EyxaWsClientStop(&g_ws);
    EyxaAmsiReaderStop(&g_amsi);
    EyxaChannelReaderStop(&g_channel);
    EyxaSysmonReaderStop(&g_sysmon);
    EyxaSenderStop(&g_sender);
    EyxaBufferClose(&g_buf);
    EyxaEnrollmentCleanup(&g_enroll);
    /* Release shared memory last so terminator.exe sees STOPPED state */
    if (g_shared_status)     UnmapViewOfFile(g_shared_status);
    if (g_status_map_handle) CloseHandle(g_status_map_handle);

    /* ── Persist cumulative events_total for next session (Option A) ── */
    SavePersistedTotal();

    if (g_console_lock_init) {
        DeleteCriticalSection(&g_console_lock);
        g_console_lock_init = FALSE;
    }
    Log(L"Eyxa stopped cleanly.");
}

/* ── Service Control Handler ─────────────────────────────────────────
 * Called by the SCM to deliver control codes to the running service.
 * Source: https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nc-winsvc-lphandler_function
 */
static VOID WINAPI EyxaServiceCtrlHandler(DWORD ctrl)
{
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
        g_svc_status.dwCurrentState = SERVICE_STOP_PENDING;
        g_svc_status.dwWaitHint     = 5000;  /* up to 5s to finish shutdown */
        SetServiceStatus(g_svc_handle, &g_svc_status);
        InterlockedExchange(&g_stopping, 1);
    }
}

/* ── Service Main ────────────────────────────────────────────────────
 * Called by StartServiceCtrlDispatcherW (in a new thread) when the SCM
 * starts the EyxaEDR service.
 * Source: https://learn.microsoft.com/en-us/windows/win32/services/writing-a-service-main-function
 */
static VOID WINAPI EyxaServiceMain(DWORD argc, LPWSTR *argv)
{
    (void)argc; (void)argv;

    /* Register the control handler so the SCM can send STOP/SHUTDOWN. */
    g_svc_handle = RegisterServiceCtrlHandlerW(EYXA_SVC_NAME, EyxaServiceCtrlHandler);
    if (!g_svc_handle) return;

    /* Immediately report SERVICE_RUNNING so the SCM does not time us out.
     * RunAgent() will log individual module failures as warnings.
     * Source: https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-setservicestatus */
    g_svc_status.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
    g_svc_status.dwCurrentState            = SERVICE_RUNNING;
    g_svc_status.dwControlsAccepted        = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_svc_status.dwWin32ExitCode           = NO_ERROR;
    g_svc_status.dwServiceSpecificExitCode = 0;
    g_svc_status.dwCheckPoint              = 0;
    g_svc_status.dwWaitHint                = 0;
    SetServiceStatus(g_svc_handle, &g_svc_status);

    RunAgent();

    /* Report SERVICE_STOPPED when RunAgent() returns. */
    g_svc_status.dwCurrentState     = SERVICE_STOPPED;
    g_svc_status.dwControlsAccepted = 0;
    SetServiceStatus(g_svc_handle, &g_svc_status);
}

/* ── Entry point ─────────────────────────────────────────────────────
 * Dual-mode: tries Windows service dispatcher first.  Falls back to
 * direct console execution when not launched by the SCM.
 * Source: https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicectrldispatcherw
 */
int wmain(void)
{
    /* Service name must exactly match the name used in `sc create`.
     * Cast to LPWSTR: the API signature is non-const but does not modify it. */
    SERVICE_TABLE_ENTRYW svc_table[] = {
        { (LPWSTR)EYXA_SVC_NAME, EyxaServiceMain },
        { NULL,                  NULL             }
    };

    g_service_mode = TRUE;  /* assume service until proven otherwise */

    if (!StartServiceCtrlDispatcherW(svc_table)) {
        if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            /* Not launched by SCM -- run interactively in console mode.
             * Enable ANSI/VT100 virtual terminal processing on stdout so the
             * live dashboard renders colors and cursor movement correctly.
             * Source: https://learn.microsoft.com/en-us/windows/console/setconsolemode */
            g_service_mode = FALSE;
            SetConsoleCtrlHandler(CtrlHandler, TRUE);

            HANDLE hout = GetStdHandle(STD_OUTPUT_HANDLE);
            if (hout != INVALID_HANDLE_VALUE) {
                DWORD con_mode = 0;
                GetConsoleMode(hout, &con_mode);
                SetConsoleMode(hout, con_mode |
                    ENABLE_VIRTUAL_TERMINAL_PROCESSING |
                    DISABLE_NEWLINE_AUTO_RETURN);
            }

            /* Start all agent modules first, then launch dashboard thread */
            RunAgent();
        }
        /* Other errors (e.g. 1073: dispatcher already running) are unexpected. */
    }
    /* In service mode StartServiceCtrlDispatcherW blocks until service stops. */
    return 0;
}
