/* Eyxa AMSI ETW reader -- Phase 3 module 2. */
#define _WIN32_WINNT 0x0602
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <winevt.h>
#include <shlobj.h>
#include <knownfolders.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <wctype.h>

#define EYXA_AMSI_SESSION L"Eyxa-Amsi-ETW"
#define EYXA_SYSMON_CHANNEL L"Microsoft-Windows-Sysmon/Operational"
#define EYXA_AMSI_EVENT_ID 1101
#define EYXA_AMSI_MAX_CONTENT (64 * 1024)
#define EYXA_AMSI_QUEUE_CAPACITY 64  /* raised from 16 – absorbs T1059 burst without drop */
#define EYXA_AMSI_CORRELATION_WINDOW_100NS (5ULL * 10000000ULL)

static const GUID EYXA_AMSI_PROVIDER = { 0x2A576B87, 0x09A7, 0x520E,
    { 0xC2, 0x1A, 0x49, 0x42, 0xF0, 0x27, 0x1D, 0x67 } };

typedef struct {
    DWORD pid, scan_result, content_size;
    ULONGLONG timestamp_filetime;
    WCHAR content_name[512], process_guid[64];
    BYTE content[EYXA_AMSI_MAX_CONTENT];
} EYXA_AMSI_EVENT;
typedef BOOL (WINAPI *EYXA_AMSI_SINK)(const EYXA_AMSI_EVENT *, void *);
typedef struct {
    TRACEHANDLE session, consumer;
    EVENT_TRACE_PROPERTIES *properties;
    HANDLE consumer_thread, worker_thread, work_event;
    CRITICAL_SECTION queue_lock;
    EYXA_AMSI_EVENT queue[EYXA_AMSI_QUEUE_CAPACITY];
    ULONG head, tail, count;
    volatile LONG stopping, failed;
    volatile LONG overflow_count;
    DWORD last_error;
    EYXA_AMSI_SINK sink;
    void *sink_context;
} EYXA_AMSI_READER;

/* The ETW callback API has no per-record context. One agent owns this module. */
static EYXA_AMSI_READER *g_eyxa_amsi_reader = NULL;

static void EyxaAmsiFail(EYXA_AMSI_READER *r, DWORD error) {
    r->last_error = error; InterlockedExchange(&r->failed, 1);
}

static BOOL EyxaAmsiRenderXml(EVT_HANDLE event, WCHAR **out) {
    DWORD used = 0, count = 0; WCHAR *xml;
    *out = NULL;
    if (EvtRender(NULL, event, EvtRenderEventXml, 0, NULL, &used, &count) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER || !used) return FALSE;
    xml = (WCHAR *)calloc(1, used + sizeof(WCHAR));
    if (!xml || !EvtRender(NULL, event, EvtRenderEventXml, used, xml, &used, &count)) {
        free(xml); return FALSE;
    }
    *out = xml; return TRUE;
}

static BOOL EyxaAmsiParseUtc(const WCHAR *xml, ULONGLONG *value) {
    /* EvtRender produces single-quoted XML attributes on this platform.
     * Confirmed by diag_sysmon_xml.exe output 2026-07-27. */
    const WCHAR *p = wcsstr(xml, L"Name='UtcTime'>"); SYSTEMTIME st = {0}; FILETIME ft;
    if (!p) return FALSE;
    p = wcschr(p, L'>'); if (!p) return FALSE; p++;
    /* Sysmon UtcTime format: "YYYY-MM-DD HH:MM:SS.sss" (space, not T, no Z)
     * Source: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon */
    if (swscanf_s(p, L"%hu-%hu-%hu %hu:%hu:%hu.%hu", &st.wYear, &st.wMonth,
        &st.wDay, &st.wHour, &st.wMinute, &st.wSecond, &st.wMilliseconds) < 6 ||
        !SystemTimeToFileTime(&st, &ft)) return FALSE;
    *value = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime; return TRUE;
}

static void EyxaAmsiProcessGuid(DWORD pid, ULONGLONG when, WCHAR *guid, DWORD chars) {
    WCHAR xpath[256], *xml = NULL, *value; EVT_HANDLE query = NULL, event = NULL;
    DWORD returned = 0; ULONGLONG best_delta = ~0ULL;
    wcsncpy_s(guid, chars, L"UNKNOWN", _TRUNCATE);
    swprintf(xpath, 256, L"*[System[EventID=1] and EventData[Data[@Name='ProcessId']='%lu']]", pid);
    query = EvtQuery(NULL, EYXA_SYSMON_CHANNEL, xpath, EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!query) return;
    while (EvtNext(query, 1, &event, 100, 0, &returned) && returned) {
        ULONGLONG candidate, delta;
        if (EyxaAmsiRenderXml(event, &xml) && EyxaAmsiParseUtc(xml, &candidate)) {
            delta = candidate > when ? candidate - when : when - candidate;
            if (delta <= EYXA_AMSI_CORRELATION_WINDOW_100NS && delta < best_delta) {
                value = wcsstr(xml, L"Name='ProcessGuid'>");
                if (value && (value = wcschr(value, L'>'))) {
                    DWORD i = 0; value++; if (*value == L'{') value++;
                    while (*value && *value != L'}' && *value != L'<' && i + 1 < chars)
                        guid[i++] = towlower(*value++);
                    guid[i] = L'\0'; best_delta = delta;
                }
            }
        }
        free(xml); xml = NULL; EvtClose(event); event = NULL;
        if (best_delta == 0) break;
    }
    if (event) EvtClose(event); if (query) EvtClose(query);
}

static BOOL EyxaAmsiParse(PEVENT_RECORD record, EYXA_AMSI_EVENT *out) {
    const BYTE *p = (const BYTE *)record->UserData, *end = p + record->UserDataLength;
    const WCHAR *ws; DWORD i = 0; UINT32 size = 0;
    if (record->UserDataLength < 13) return FALSE;
    ZeroMemory(out, sizeof(*out)); out->pid = record->EventHeader.ProcessId;
    out->timestamp_filetime = (ULONGLONG)record->EventHeader.TimeStamp.QuadPart;
    p += 9; memcpy(&out->scan_result, p, 4); p += 4;
    ws = (const WCHAR *)p;
    while ((const BYTE *)(ws + 1) <= end && *ws && i + 1 < ARRAYSIZE(out->content_name)) out->content_name[i++] = *ws++;
    if ((const BYTE *)(ws + 1) > end) return FALSE; ws++; p = (const BYTE *)ws;
    ws = (const WCHAR *)p; while ((const BYTE *)(ws + 1) <= end && *ws) ws++;
    if ((const BYTE *)(ws + 1) > end || (const BYTE *)(ws + 1) + 8 > end) return TRUE;
    p = (const BYTE *)(ws + 1); memcpy(&size, p, 4); p += 8;
    if (size > EYXA_AMSI_MAX_CONTENT) {
        /* M-2 fix: write to log file directly — this callback runs on the ETW
         * thread pool, not the main thread, so wprintf is wrong in service mode
         * (no console) and bypasses g_console_lock in console mode. */
        FILE *_lf = NULL;
        if (_wfopen_s(&_lf, L"C:\\ProgramData\\Eyxa\\eyxa.log", L"a, ccs=UTF-8") == 0 && _lf) {
            fwprintf(_lf, L"[eyxa] WARNING: AMSI content truncated (%lu bytes > %d KB cap)\n",
                     (unsigned long)size, EYXA_AMSI_MAX_CONTENT / 1024);
            fclose(_lf);
        }
    }
    out->content_size = size > EYXA_AMSI_MAX_CONTENT ? EYXA_AMSI_MAX_CONTENT : size;
    if (p + out->content_size > end) out->content_size = (DWORD)(end - p);
    if (out->content_size) memcpy(out->content, p, out->content_size);
    return TRUE;
}

static VOID WINAPI EyxaAmsiCallback(PEVENT_RECORD record) {
    EYXA_AMSI_READER *r = g_eyxa_amsi_reader; EYXA_AMSI_EVENT event;
    if (!r || InterlockedCompareExchange(&r->stopping, 0, 0) ||
        record->EventHeader.EventDescriptor.Id != EYXA_AMSI_EVENT_ID || !EyxaAmsiParse(record, &event)) return;
    EnterCriticalSection(&r->queue_lock);
    if (r->count == EYXA_AMSI_QUEUE_CAPACITY) InterlockedIncrement(&r->overflow_count);
    else { r->queue[r->head] = event; r->head = (r->head + 1) % EYXA_AMSI_QUEUE_CAPACITY; r->count++; SetEvent(r->work_event); }
    LeaveCriticalSection(&r->queue_lock);
}

static DWORD WINAPI EyxaAmsiWorker(void *context) {
    EYXA_AMSI_READER *r = context;
    for (;;) { EYXA_AMSI_EVENT event; BOOL got = FALSE;
        WaitForSingleObject(r->work_event, 250); EnterCriticalSection(&r->queue_lock);
        if (r->count) { event = r->queue[r->tail]; r->tail = (r->tail + 1) % EYXA_AMSI_QUEUE_CAPACITY; r->count--; got = TRUE; }
        LeaveCriticalSection(&r->queue_lock);
        if (!got) { if (InterlockedCompareExchange(&r->stopping, 0, 0)) break; continue; }
        EyxaAmsiProcessGuid(event.pid, event.timestamp_filetime, event.process_guid, ARRAYSIZE(event.process_guid));
        /* H-2 fix: sink failure (e.g. buffer full / disk) is transient and non-fatal.
         * Drop the event rather than permanently killing the AMSI module. The module
         * will continue processing the next event normally. */
        r->sink(&event, r->sink_context);
    } return 0;
}

static DWORD WINAPI EyxaAmsiConsumer(void *context) {
    EYXA_AMSI_READER *r = context; EVENT_TRACE_LOGFILEW log = {0};
    log.LoggerName = EYXA_AMSI_SESSION; log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = EyxaAmsiCallback;
    r->consumer = OpenTraceW(&log); if (r->consumer == INVALID_PROCESSTRACE_HANDLE) { EyxaAmsiFail(r, GetLastError()); return 1; }
    ProcessTrace(&r->consumer, 1, NULL, NULL); return 0;
}

BOOL EyxaAmsiReaderStart(EYXA_AMSI_READER *r, EYXA_AMSI_SINK sink, void *context) {
    DWORD bytes; ULONG status; WCHAR *name; ENABLE_TRACE_PARAMETERS parameters = {0};
    if (!r || !sink) return FALSE; ZeroMemory(r, sizeof(*r)); r->session = r->consumer = INVALID_PROCESSTRACE_HANDLE; r->sink = sink; r->sink_context = context;
    InitializeCriticalSection(&r->queue_lock); r->work_event = CreateEventW(NULL, FALSE, FALSE, NULL); if (!r->work_event) goto fail;
    bytes = sizeof(EVENT_TRACE_PROPERTIES) + (DWORD)((wcslen(EYXA_AMSI_SESSION) + 1) * sizeof(WCHAR));
    r->properties = calloc(1, bytes); if (!r->properties) goto fail;
    r->properties->Wnode.BufferSize = bytes; r->properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID; r->properties->Wnode.ClientContext = 2;
    r->properties->BufferSize = 64; r->properties->MinimumBuffers = 4; r->properties->MaximumBuffers = 16; r->properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE; r->properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    name = (WCHAR *)((BYTE *)r->properties + r->properties->LoggerNameOffset); wcscpy_s(name, wcslen(EYXA_AMSI_SESSION) + 1, EYXA_AMSI_SESSION);
    status = StartTraceW(&r->session, EYXA_AMSI_SESSION, r->properties); if (status == ERROR_ALREADY_EXISTS) { ControlTraceW(0, EYXA_AMSI_SESSION, r->properties, EVENT_TRACE_CONTROL_STOP); status = StartTraceW(&r->session, EYXA_AMSI_SESSION, r->properties); }
    if (status != ERROR_SUCCESS) { r->last_error = status; goto fail; }
    parameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2; status = EnableTraceEx2(r->session, &EYXA_AMSI_PROVIDER, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, ~0ULL, 0, 0, &parameters);
    if (status != ERROR_SUCCESS && status != ERROR_TIMEOUT) { r->last_error = status; goto fail; }
    g_eyxa_amsi_reader = r;
    r->worker_thread = CreateThread(NULL, 0, EyxaAmsiWorker, r, 0, NULL); r->consumer_thread = CreateThread(NULL, 0, EyxaAmsiConsumer, r, 0, NULL);
    if (!r->worker_thread || !r->consumer_thread) { r->last_error = GetLastError(); goto fail; } return TRUE;
fail: InterlockedExchange(&r->stopping, 1); if (r->session != INVALID_PROCESSTRACE_HANDLE) ControlTraceW(r->session, NULL, r->properties, EVENT_TRACE_CONTROL_STOP); if (r->work_event) CloseHandle(r->work_event); if (r->properties) free(r->properties); DeleteCriticalSection(&r->queue_lock); return FALSE;
}

void EyxaAmsiReaderStop(EYXA_AMSI_READER *r) {
    if (!r) return; InterlockedExchange(&r->stopping, 1);
    if (r->consumer != INVALID_PROCESSTRACE_HANDLE) CloseTrace(r->consumer);
    if (r->session != INVALID_PROCESSTRACE_HANDLE) ControlTraceW(r->session, NULL, r->properties, EVENT_TRACE_CONTROL_STOP);
    if (r->work_event) SetEvent(r->work_event); if (r->consumer_thread) { WaitForSingleObject(r->consumer_thread, 5000); CloseHandle(r->consumer_thread); }
    if (r->worker_thread) { WaitForSingleObject(r->worker_thread, 5000); CloseHandle(r->worker_thread); }
    if (r->work_event) CloseHandle(r->work_event); free(r->properties); g_eyxa_amsi_reader = NULL; DeleteCriticalSection(&r->queue_lock);
}

BOOL EyxaAmsiReaderFailed(const EYXA_AMSI_READER *r, DWORD *error) { if (error) *error = r ? r->last_error : ERROR_INVALID_PARAMETER; return !r || InterlockedCompareExchange((volatile LONG *)&r->failed, 0, 0) != 0; }
LONG EyxaAmsiReaderOverflowCount(const EYXA_AMSI_READER *r) { return r ? InterlockedCompareExchange((volatile LONG *)&r->overflow_count, 0, 0) : 0; }
