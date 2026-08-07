/*
 * dns_reader.c -- ETW-based DNS client telemetry reader (A7).
 *
 * Subscribes to the Microsoft-Windows-DNS-Client ETW provider to capture
 * every DNS query made by every process on the machine.
 * GUID: {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}
 * Source: https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal
 * Provider manifest: wevtutil gp Microsoft-Windows-DNS-Client
 *
 * Event IDs captured:
 *   EID 3006 - DNS query initiated (QueryName, QueryType, ProcessId)
 *   EID 3008 - DNS query completed (QueryName, QueryResults, ProcessId)
 *   EID 3010 - DNS query from cache (QueryName, QueryResults, ProcessId)
 *
 * Source for keyword/level filtering:
 * https://learn.microsoft.com/en-us/windows/win32/etw/enabletraceex2
 *
 * Uses the same TDH-based pattern as amsi_reader.c (Phase 3, Module 2).
 * Falls back gracefully if the provider is not registered on this Windows
 * edition (e.g. Windows Server Core).
 *
 * Unity-build: included from main.c, not compiled separately.
 */

#ifndef EYXA_DNS_READER_C
#define EYXA_DNS_READER_C

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0602
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>

/* TRACE_LEVEL_INFORMATIONAL = 4 per ETW specification.
 * Defined in evntrace.h in recent Windows SDK versions; guard for older ones.
 * Source: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2 */
#ifndef TRACE_LEVEL_INFORMATIONAL
#define TRACE_LEVEL_INFORMATIONAL 4
#endif
#include <tdh.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* DNS-Client ETW provider GUID.
 * Verified on this system via: wevtutil gp Microsoft-Windows-DNS-Client
 * Source: https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal */
static const GUID EYXA_DNS_PROVIDER_GUID = {
    0x1C95126E, 0x7EEA, 0x49A9,
    { 0xA3, 0xFE, 0xA3, 0x78, 0xB0, 0x3D, 0xDB, 0x4D }
};

/* EIDs we care about from DNS-Client */
#define EYXA_DNS_EID_QUERY_INIT   3006
#define EYXA_DNS_EID_QUERY_DONE   3008
#define EYXA_DNS_EID_CACHE_HIT    3010

#define EYXA_DNS_SESSION_NAME L"EyxaDNSSession"
#define EYXA_DNS_PROPS_SIZE   (sizeof(EVENT_TRACE_PROPERTIES) + \
                               sizeof(EYXA_DNS_SESSION_NAME))

typedef BOOL (WINAPI *EYXA_DNS_SINK)(const char *json, void *context);

typedef struct {
    TRACEHANDLE    session_handle;
    TRACEHANDLE    consumer_handle;
    HANDLE         consumer_thread;
    EYXA_DNS_SINK  sink;
    void          *sink_context;
    volatile LONG  stopping;
    volatile LONG  failed;
} EYXA_DNS_READER;

/* Module-level pointer so the static ETW callback can reach it.
 * One DNS reader per process — acceptable for a single-binary agent. */
static EYXA_DNS_READER *g_dns_reader_ptr = NULL;

/* ── Utility: extract a wide string property from a TDH event record ── */
static BOOL DnsGetWStrProperty(PEVENT_RECORD rec, LPCWSTR prop_name,
                               WCHAR *out, DWORD out_chars)
{
    BYTE  buf[512];
    DWORD buf_size = sizeof(buf);
    PROPERTY_DATA_DESCRIPTOR desc = { (ULONGLONG)(ULONG_PTR)prop_name, ULONG_MAX, 0 };

    if (TdhGetProperty(rec, 0, NULL, 1, &desc, buf_size, buf) != ERROR_SUCCESS)
        return FALSE;
    /* property is a counted WCHAR string */
    wcsncpy_s(out, out_chars, (WCHAR *)buf, _TRUNCATE);
    return TRUE;
}

static BOOL DnsGetDwordProperty(PEVENT_RECORD rec, LPCWSTR prop_name, DWORD *out)
{
    DWORD buf_size = sizeof(DWORD);
    PROPERTY_DATA_DESCRIPTOR desc = { (ULONGLONG)(ULONG_PTR)prop_name, ULONG_MAX, 0 };
    return TdhGetProperty(rec, 0, NULL, 1, &desc, buf_size, (PBYTE)out) == ERROR_SUCCESS;
}

/* H-3 fix: Proper JSON string escaping for DNS field values.
 * Replaces the old "replace quote with apostrophe" hack which left backslashes,
 * newlines, and control chars unescaped, causing HTTP 400 on ingest.
 * Source: https://www.rfc-editor.org/rfc/rfc8259#section-7 */
static void DnsJsonEscape(const char *src, char *dst, size_t dst_max)
{
    size_t i = 0;
    for (const char *p = src; *p && i + 8 < dst_max; p++) {
        unsigned char c = (unsigned char)*p;
        if      (c == '"')  { dst[i++] = '\\'; dst[i++] = '"'; }
        else if (c == '\\') { dst[i++] = '\\'; dst[i++] = '\\'; }
        else if (c == '\n') { dst[i++] = '\\'; dst[i++] = 'n'; }
        else if (c == '\r') { dst[i++] = '\\'; dst[i++] = 'r'; }
        else if (c == '\t') { dst[i++] = '\\'; dst[i++] = 't'; }
        else if (c < 0x20) {
            int _n = _snprintf_s(dst+i, dst_max-i, _TRUNCATE, "\\u%04x", c);
            if (_n > 0) i += _n;
        } else { dst[i++] = (char)c; }
    }
    dst[i] = '\0';
}

/* ── ETW event callback ── */
static VOID WINAPI DnsEventCallback(PEVENT_RECORD rec)
{
    EYXA_DNS_READER *reader = g_dns_reader_ptr;
    WORD  eid;
    WCHAR query_name[256]   = {0};
    WCHAR query_result[512] = {0};
    DWORD pid               = 0;
    DWORD qtype             = 0;
    char  json[1024];
    char  ts[32];
    SYSTEMTIME st;

    if (!reader || InterlockedCompareExchange(&reader->stopping, 0, 0))
        return;

    eid = rec->EventHeader.EventDescriptor.Id;
    if (eid != EYXA_DNS_EID_QUERY_INIT &&
        eid != EYXA_DNS_EID_QUERY_DONE &&
        eid != EYXA_DNS_EID_CACHE_HIT)
        return;

    /* Extract fields - best-effort, drop on failure */
    if (!DnsGetWStrProperty(rec, L"QueryName", query_name, ARRAYSIZE(query_name)))
        return;

    DnsGetDwordProperty(rec, L"ProcessId", &pid);
    DnsGetDwordProperty(rec, L"QueryType", &qtype);
    DnsGetWStrProperty(rec, L"QueryResults", query_result, ARRAYSIZE(query_result));

    /* Timestamp from event header (100ns intervals since Jan 1, 1601) */
    FileTimeToSystemTime((FILETIME *)&rec->EventHeader.TimeStamp, &st);
    _snprintf_s(ts, sizeof(ts), _TRUNCATE,
        "%04d-%02d-%02dT%02d:%02d:%02dZ",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);

    /* Convert WCHAR fields to UTF-8 for JSON */
    char qname_u8[512]  = {0};
    char qresult_u8[512] = {0};
    WideCharToMultiByte(CP_UTF8, 0, query_name,   -1, qname_u8,   sizeof(qname_u8)-1,   NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, query_result, -1, qresult_u8, sizeof(qresult_u8)-1, NULL, NULL);

    /* H-3 fix: use proper JSON escaping instead of naive quote substitution */
    char qname_esc[1024]   = {0};
    char qresult_esc[1024] = {0};
    DnsJsonEscape(qname_u8,   qname_esc,   sizeof(qname_esc));
    DnsJsonEscape(qresult_u8, qresult_esc, sizeof(qresult_esc));

    _snprintf_s(json, sizeof(json), _TRUNCATE,
        "{"
        "\"EventID\":%d,"
        "\"Channel\":\"Microsoft-Windows-DNS-Client/Operational\","
        "\"TimeCreated\":\"%s\","
        "\"source\":\"dns\","
        "\"QueryName\":\"%s\","
        "\"QueryType\":%lu,"
        "\"QueryResults\":\"%s\","
        "\"ProcessId\":%lu"
        "}",
        eid, ts, qname_esc, (unsigned long)qtype,
        qresult_esc, (unsigned long)pid);

    if (reader->sink)
        reader->sink(json, reader->sink_context);
}

/* ── Consumer thread: blocks on ProcessTrace ── */
static DWORD WINAPI DnsConsumerThread(LPVOID param)
{
    EYXA_DNS_READER *reader = (EYXA_DNS_READER *)param;
    ProcessTrace(&reader->consumer_handle, 1, NULL, NULL);
    /* L-4 fix: if ProcessTrace returned while we were NOT stopping, the ETW
     * session died unexpectedly — mark the module as failed so the heartbeat
     * thread can surface the degraded state. */
    if (!InterlockedCompareExchange(&reader->stopping, 0, 0))
        InterlockedExchange(&reader->failed, 1);
    return 0;
}

/* ── Public API ── */
BOOL EyxaDnsReaderStart(EYXA_DNS_READER *reader, EYXA_DNS_SINK sink, void *ctx)
{
    ULONG status;
    BYTE  props_buf[EYXA_DNS_PROPS_SIZE];
    EVENT_TRACE_PROPERTIES *props = (EVENT_TRACE_PROPERTIES *)props_buf;
    EVENT_TRACE_LOGFILEW    logfile = {0};

    if (!reader || !sink) return FALSE;
    ZeroMemory(reader, sizeof(*reader));
    reader->sink         = sink;
    reader->sink_context = ctx;
    reader->session_handle   = INVALID_PROCESSTRACE_HANDLE;
    reader->consumer_handle  = INVALID_PROCESSTRACE_HANDLE;

    /* Stop any leftover session from a previous crash */
    ZeroMemory(props_buf, sizeof(props_buf));
    props->Wnode.BufferSize    = EYXA_DNS_PROPS_SIZE;
    props->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
    props->LogFileNameOffset   = 0;
    props->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);
    ControlTraceW(0, EYXA_DNS_SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);

    /* Create a new real-time ETW session
     * Source: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracew */
    ZeroMemory(props_buf, sizeof(props_buf));
    props->Wnode.BufferSize    = EYXA_DNS_PROPS_SIZE;
    props->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
    props->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
    props->LogFileNameOffset   = 0;
    props->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);
    wcscpy_s((WCHAR *)((BYTE *)props + props->LoggerNameOffset),
              sizeof(EYXA_DNS_SESSION_NAME) / sizeof(WCHAR),
              EYXA_DNS_SESSION_NAME);

    status = StartTraceW(&reader->session_handle, EYXA_DNS_SESSION_NAME, props);
    if (status != ERROR_SUCCESS) {
        reader->session_handle = INVALID_PROCESSTRACE_HANDLE;
        return FALSE;
    }

    /* Enable the DNS-Client provider at Informational level, all keywords
     * Source: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2 */
    status = EnableTraceEx2(reader->session_handle, &EYXA_DNS_PROVIDER_GUID,
                            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_INFORMATIONAL,
                            0xFFFFFFFFFFFFFFFF,  /* all keywords */
                            0, 0, NULL);
    if (status != ERROR_SUCCESS) {
        ControlTraceW(reader->session_handle, NULL, props, EVENT_TRACE_CONTROL_STOP);
        return FALSE;
    }

    /* Open a real-time consumer
     * Source: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-opentracew */
    logfile.LoggerName          = EYXA_DNS_SESSION_NAME;
    logfile.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME |
                                  PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = DnsEventCallback;
    reader->consumer_handle     = OpenTraceW(&logfile);
    if (reader->consumer_handle == INVALID_PROCESSTRACE_HANDLE) {
        ControlTraceW(reader->session_handle, NULL, props, EVENT_TRACE_CONTROL_STOP);
        return FALSE;
    }

    g_dns_reader_ptr = reader;

    reader->consumer_thread = CreateThread(NULL, 0, DnsConsumerThread, reader, 0, NULL);
    if (!reader->consumer_thread) {
        CloseTrace(reader->consumer_handle);
        ControlTraceW(reader->session_handle, NULL, props, EVENT_TRACE_CONTROL_STOP);
        return FALSE;
    }
    return TRUE;
}

void EyxaDnsReaderStop(EYXA_DNS_READER *reader)
{
    BYTE  props_buf[EYXA_DNS_PROPS_SIZE];
    EVENT_TRACE_PROPERTIES *props = (EVENT_TRACE_PROPERTIES *)props_buf;

    if (!reader) return;
    InterlockedExchange(&reader->stopping, 1);
    g_dns_reader_ptr = NULL;

    if (reader->consumer_handle != INVALID_PROCESSTRACE_HANDLE)
        CloseTrace(reader->consumer_handle);

    if (reader->session_handle != INVALID_PROCESSTRACE_HANDLE) {
        ZeroMemory(props_buf, sizeof(props_buf));
        props->Wnode.BufferSize  = EYXA_DNS_PROPS_SIZE;
        props->Wnode.Flags       = WNODE_FLAG_TRACED_GUID;
        props->LoggerNameOffset  = sizeof(EVENT_TRACE_PROPERTIES);
        ControlTraceW(reader->session_handle, NULL, props, EVENT_TRACE_CONTROL_STOP);
    }

    if (reader->consumer_thread) {
        WaitForSingleObject(reader->consumer_thread, 3000);
        CloseHandle(reader->consumer_thread);
    }
}

BOOL EyxaDnsReaderFailed(const EYXA_DNS_READER *reader)
{
    if (!reader) return TRUE;
    return InterlockedCompareExchange((volatile LONG *)&reader->failed, 0, 0) != 0;
}

#endif /* EYXA_DNS_READER_C */
