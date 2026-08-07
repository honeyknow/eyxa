#ifndef EYXA_CHANNEL_READER_C
#define EYXA_CHANNEL_READER_C
/*
 * Eyxa channel reader - Expansion Phase B.
 *
 * Generic, config-driven Windows Event Log subscription module.
 * Parses agent/config/eyxa.xml (or a caller-supplied override path),
 * opens one EvtSubscribe call per <Channel> element, and delivers raw
 * EvtRender XML to the caller's sink callback - identical contract to
 * sysmon_reader.c's EYXA_EVENT_SINK.
 *
 * Adding a new technique's telemetry requires ONLY an eyxa.xml edit and
 * an agent restart - zero code changes, zero recompilation.
 *
 * Unity-build dependencies (must be included before this file in main.c):
 *   sysmon_reader.c  - defines EYXA_EVENT_SINK typedef
 *
 * This file is otherwise self-contained (Windows APIs + CRT only).
 *
 * Source (EvtSubscribe API):
 *   https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtsubscribe
 * Source (XPath query syntax):
 *   https://learn.microsoft.com/en-us/windows/win32/wes/consuming-events#xpath-10-queries
 * Source (GetModuleFileNameW):
 *   https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulefilenamew
 */

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0602
#include <windows.h>
#include <winevt.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

/* ── limits ─────────────────────────────────────────────────────────── */
#define EYXA_CR_MAX_CHANNELS   64    /* raised from 16 – silently capped new channels */
#define EYXA_CR_MAX_EID        64    /* raised from 32 – Security channel needs 30+ EIDs */
#define EYXA_CR_XPATH_MAX      2048  /* raised from 512 – 32-EID OR-chain already ~580 chars */
#define EYXA_CR_CHANNEL_MAX    256
#define EYXA_CR_XML_FILE_MAX   (256 * 1024)   /* 256 KB max eyxa.xml size */

/* ── per-subscription state ──────────────────────────────────────────── */
typedef struct {
    EVT_HANDLE      subscription;
    WCHAR           channel[EYXA_CR_CHANNEL_MAX];
    WCHAR           xpath[EYXA_CR_XPATH_MAX];
    EYXA_EVENT_SINK sink;          /* from sysmon_reader.c (same unity TU) */
    void           *sink_context;
    volatile LONG   stopping;
    volatile LONG   callbacks_inflight;
    volatile LONG   failed;
    DWORD           last_error;
} EYXA_CHANNEL_ENTRY;

/* ── reader state (one instance per agent) ───────────────────────────── */
typedef struct {
    EYXA_CHANNEL_ENTRY entries[EYXA_CR_MAX_CHANNELS];
    DWORD              count;     /* total parsed from config */
} EYXA_CHANNEL_READER;


/* ── private: render EVT_HANDLE → XML wide-char string ──────────────── */
/*
 * Named EyxaChRenderXml (not EyxaRenderXml) to avoid collision with the
 * identically-named static function in sysmon_reader.c within the unity build.
 */
static BOOL EyxaChRenderXml(EVT_HANDLE handle, EVT_RENDER_FLAGS flag,
                              WCHAR **xml_out)
{
    DWORD used = 0, prop_count = 0;
    if (!xml_out) return FALSE;
    *xml_out = NULL;

    /* First call: measure required buffer size */
    EvtRender(NULL, handle, flag, 0, NULL, &used, &prop_count);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || used == 0) return FALSE;

    WCHAR *xml = (WCHAR *)calloc(1, used + sizeof(WCHAR));
    if (!xml) return FALSE;

    if (!EvtRender(NULL, handle, flag, used, xml, &used, &prop_count)) {
        free(xml);
        return FALSE;
    }
    *xml_out = xml;
    return TRUE;
}


/* ── private: EvtSubscribe delivery callback ─────────────────────────── */
static DWORD WINAPI EyxaChCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action,
                                    PVOID context, EVT_HANDLE event)
{
    EYXA_CHANNEL_ENTRY *entry = (EYXA_CHANNEL_ENTRY *)context;
    WCHAR *event_xml = NULL;

    if (!entry) return ERROR_SUCCESS;
    InterlockedIncrement(&entry->callbacks_inflight);

    if (InterlockedCompareExchange(&entry->stopping, 0, 0)) goto done;

    if (action == EvtSubscribeActionError) {
        entry->last_error = (DWORD)(ULONG_PTR)event;
        InterlockedExchange(&entry->failed, 1);
        goto done;
    }
    if (action != EvtSubscribeActionDeliver) goto done;

    if (!EyxaChRenderXml(event, EvtRenderEventXml, &event_xml) ||
        !entry->sink ||
        !entry->sink(entry->channel, event_xml, entry->sink_context)) {
        /* P-1 fix: sink failure (e.g. buffer full) is non-fatal.
         * Do NOT set failed=1 — a transient write failure must not permanently
         * kill Security/PowerShell/WMI coverage until the next service restart.
         * Record last_error for diagnostics; event is dropped (at-most-once). */
        entry->last_error = GetLastError();
    }

done:
    free(event_xml);
    InterlockedDecrement(&entry->callbacks_inflight);
    return ERROR_SUCCESS;
}


/* ── private: extract double-quoted XML attribute value ──────────────── */
/*
 * Looks for: attr="value" in text.
 * Writes value into out (wide), returns length, or 0 on failure.
 * eyxa.xml uses double-quoted attributes (unlike EvtRender XML which uses
 * single quotes) - hence a separate helper from normalizer.c's xml_attr().
 */
static DWORD EyxaChDqAttr(const WCHAR *text, const WCHAR *attr,
                            WCHAR *out, DWORD out_max)
{
    WCHAR pat[128];
    if (swprintf(pat, ARRAYSIZE(pat), L"%ls=\"", attr) < 0) return 0;
    const WCHAR *p = wcsstr(text, pat);
    if (!p) return 0;
    p += wcslen(pat);
    const WCHAR *end = wcschr(p, L'"');
    if (!end) return 0;
    DWORD len = (DWORD)(end - p);
    if (len == 0 || len >= out_max) return 0;
    wcsncpy_s(out, out_max, p, len);
    out[len] = L'\0';
    return len;
}


/* ── private: read file from disk → wide-char buffer (UTF-8 decode) ─── */
static BOOL EyxaChReadFileW(const WCHAR *path, WCHAR **out, DWORD *out_chars)
{
    HANDLE fh = INVALID_HANDLE_VALUE;
    LARGE_INTEGER sz = {0};
    DWORD read_bytes = 0;
    char  *raw  = NULL;
    WCHAR *wide = NULL;
    BOOL   ok   = FALSE;

    fh = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                     OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh == INVALID_HANDLE_VALUE) return FALSE;

    if (!GetFileSizeEx(fh, &sz) || sz.QuadPart <= 0 ||
        sz.QuadPart > EYXA_CR_XML_FILE_MAX)
        goto done;

    raw = (char *)malloc((size_t)sz.QuadPart + 1);
    if (!raw) goto done;

    if (!ReadFile(fh, raw, (DWORD)sz.QuadPart, &read_bytes, NULL) ||
        read_bytes != (DWORD)sz.QuadPart)
        goto done;
    raw[read_bytes] = '\0';

    /* UTF-8 → wide chars
     * Source: https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-multibytetowidechar */
    int needed = MultiByteToWideChar(CP_UTF8, 0, raw, (int)read_bytes, NULL, 0);
    if (needed <= 0) goto done;
    wide = (WCHAR *)calloc((size_t)needed + 1, sizeof(WCHAR));
    if (!wide) goto done;
    MultiByteToWideChar(CP_UTF8, 0, raw, (int)read_bytes, wide, needed);
    wide[needed] = L'\0';

    *out       = wide; wide = NULL;
    *out_chars = (DWORD)needed;
    ok = TRUE;

done:
    free(wide);
    free(raw);
    if (fh != INVALID_HANDLE_VALUE) CloseHandle(fh);
    return ok;
}


/* ── private: build XPath from an EventID list ───────────────────────── */
/*
 * 1 EID:  *[System[EventID=1102]]
 * 2+ EID: *[System[(EventID=1102 or EventID=4698)]]
 * Source: https://learn.microsoft.com/en-us/windows/win32/wes/consuming-events#xpath-10-queries
 */
static BOOL EyxaChBuildXPath(const DWORD *eids, DWORD eid_count,
                               WCHAR *xpath, DWORD xpath_max)
{
    if (eid_count == 0 || !eids || !xpath || xpath_max < 32) return FALSE;

    if (eid_count == 1) {
        return swprintf(xpath, xpath_max,
                        L"*[System[EventID=%lu]]", (unsigned long)eids[0]) > 0;
    }

    int pos = swprintf(xpath, xpath_max, L"*[System[(");
    if (pos < 0) return FALSE;
    for (DWORD i = 0; i < eid_count; i++) {
        int n;
        if (i == 0)
            n = swprintf(xpath + pos, (size_t)(xpath_max - pos),
                         L"EventID=%lu", (unsigned long)eids[i]);
        else
            n = swprintf(xpath + pos, (size_t)(xpath_max - pos),
                         L" or EventID=%lu", (unsigned long)eids[i]);
        if (n < 0 || (DWORD)(pos + n) >= xpath_max) return FALSE;
        pos += n;
    }
    return swprintf(xpath + pos, (size_t)(xpath_max - pos), L")]]") > 0;
}


/* ── private: parse eyxa.xml wide-char text → reader->entries[] ─────── */
static BOOL EyxaChParseConfig(const WCHAR *xml, EYXA_CHANNEL_READER *reader)
{
    const WCHAR *cur = xml;
    reader->count = 0;

    while (reader->count < EYXA_CR_MAX_CHANNELS) {
        /* Find next <Channel */
        cur = wcsstr(cur, L"<Channel");
        if (!cur) break;

        EYXA_CHANNEL_ENTRY *entry = &reader->entries[reader->count];
        ZeroMemory(entry, sizeof(*entry));

        /* Extract channel name="..." */
        if (!EyxaChDqAttr(cur, L"name", entry->channel, EYXA_CR_CHANNEL_MAX)) {
            cur++;
            continue;
        }

        /* Find </Channel> to bound the event-ID scan */
        const WCHAR *block_end = wcsstr(cur, L"</Channel>");
        if (!block_end) break;

        /* Collect <EventID>N</EventID> elements within this channel block */
        DWORD eids[EYXA_CR_MAX_EID];
        DWORD eid_count = 0;
        const WCHAR *scan = cur;

        while (scan < block_end && eid_count < EYXA_CR_MAX_EID) {
            const WCHAR *open = wcsstr(scan, L"<EventID>");
            if (!open || open >= block_end) break;
            open += wcslen(L"<EventID>");

            const WCHAR *close = wcsstr(open, L"</EventID>");
            if (!close || close >= block_end) break;

            DWORD num_len = (DWORD)(close - open);
            if (num_len > 0 && num_len < 8) {
                WCHAR nbuf[8] = {0};
                wcsncpy_s(nbuf, ARRAYSIZE(nbuf), open, num_len);
                DWORD eid = (DWORD)wcstoul(nbuf, NULL, 10);
                if (eid > 0) eids[eid_count++] = eid;
            }
            scan = close + 1;
        }

        if (eid_count > 0 &&
            EyxaChBuildXPath(eids, eid_count, entry->xpath, EYXA_CR_XPATH_MAX)) {
            reader->count++;
        }

        cur = block_end + 1;
    }

    return reader->count > 0;
}


/* ── private: resolve eyxa.xml path relative to the agent binary ─────── */
static BOOL EyxaChFindConfigPath(WCHAR *path, DWORD path_max)
{
    WCHAR exe[MAX_PATH];
    /* Source: https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulefilenamew */
    if (!GetModuleFileNameW(NULL, exe, MAX_PATH)) return FALSE;
    WCHAR *slash = wcsrchr(exe, L'\\');
    if (!slash) return FALSE;
    *slash = L'\0';   /* strip filename, keep directory */
    return swprintf(path, path_max, L"%ls\\eyxa.xml", exe) > 0;
}


/* ══ public API ═════════════════════════════════════════════════════════ */

/*
 * EyxaChannelReaderStart
 *
 * Parses eyxa.xml (from config_path_override if non-NULL, otherwise the
 * directory of the running binary), then opens one EvtSubscribe per
 * <Channel> element.
 *
 * Returns TRUE if at least one subscription was successfully opened.
 * Partial success is allowed - entries where EvtSubscribe fails are skipped.
 *
 * sink        - callback matching EYXA_EVENT_SINK (from sysmon_reader.c)
 * sink_context - passed through to the callback as-is
 * config_path_override - full path to eyxa.xml, or NULL to auto-detect
 */
BOOL EyxaChannelReaderStart(EYXA_CHANNEL_READER *reader,
                              EYXA_EVENT_SINK      sink,
                              void                *sink_context,
                              const WCHAR         *config_path_override)
{
    if (!reader || !sink) return FALSE;
    ZeroMemory(reader, sizeof(*reader));

    /* Resolve eyxa.xml path */
    WCHAR config_path[MAX_PATH];
    if (config_path_override && config_path_override[0]) {
        wcsncpy_s(config_path, MAX_PATH, config_path_override, _TRUNCATE);
    } else {
        if (!EyxaChFindConfigPath(config_path, MAX_PATH)) return FALSE;
    }

    /* Read file → wide chars */
    WCHAR *xml_text  = NULL;
    DWORD  xml_chars = 0;
    if (!EyxaChReadFileW(config_path, &xml_text, &xml_chars)) return FALSE;

    BOOL parsed = EyxaChParseConfig(xml_text, reader);
    free(xml_text);
    if (!parsed) return FALSE;

    /* Open subscriptions */
    DWORD started = 0;
    for (DWORD i = 0; i < reader->count; i++) {
        EYXA_CHANNEL_ENTRY *e = &reader->entries[i];
        e->sink         = sink;
        e->sink_context = sink_context;

        /* Source: https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtsubscribe */
        e->subscription = EvtSubscribe(
            NULL,                        /* session: local machine */
            NULL,                        /* signal event: NULL → callback mode */
            e->channel,
            e->xpath,
            NULL,                        /* bookmark: NULL → future events only */
            e,
            EyxaChCallback,
            EvtSubscribeToFutureEvents
        );
        if (e->subscription != NULL) {
            started++;
        } else {
            e->last_error = GetLastError();
        }
    }

    return started > 0;
}

/*
 * EyxaChannelReaderStop - graceful shutdown of all subscriptions.
 * Waits for in-flight callbacks to complete before returning.
 */
void EyxaChannelReaderStop(EYXA_CHANNEL_READER *reader)
{
    if (!reader) return;
    for (DWORD i = 0; i < reader->count; i++) {
        EYXA_CHANNEL_ENTRY *e = &reader->entries[i];
        InterlockedExchange(&e->stopping, 1);
        if (e->subscription) EvtClose(e->subscription);
        while (InterlockedCompareExchange(&e->callbacks_inflight, 0, 0) != 0)
            Sleep(1);
        e->subscription = NULL;
    }
}

/*
 * EyxaChannelReaderStarted - returns count of successfully opened subscriptions.
 */
DWORD EyxaChannelReaderStarted(const EYXA_CHANNEL_READER *reader)
{
    if (!reader) return 0;
    DWORD n = 0;
    for (DWORD i = 0; i < reader->count; i++)
        if (reader->entries[i].subscription != NULL) n++;
    return n;
}

#endif /* EYXA_CHANNEL_READER_C */
