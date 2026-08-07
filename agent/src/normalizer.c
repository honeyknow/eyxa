#ifndef EYXA_NORMALIZER_C
#define EYXA_NORMALIZER_C
/*
 * Eyxa event normaliser - Phase 4 module.
 *
 * Two public functions:
 *
 *   EyxaNormalizeSysmonXml
 *     Takes a Sysmon EvtRender XML string (single-quoted attributes,
 *     confirmed 2026-07-27 from real system capture), walks every
 *     <Data Name='...'> element in EventData, and emits a UTF-8 JSON
 *     object suitable for storage in events.payload.
 *
 *     The promoted fields (EventID, Channel, TimeCreated, source) are
 *     written into the supplied EYXA_NORM_META structure so the caller
 *     can pass them to the ingest endpoint's promoted columns separately.
 *
 *     The special key "__raw__" is appended last, containing the original
 *     XML string so the backend can store it in events.raw_json.
 *
 *   EyxaNormalizeAmsiEvent
 *     Takes an EYXA_AMSI_EVENT (from amsi_reader.c), emits the same
 *     JSON shape with ContentName, ScanResult, Content, ProcessId,
 *     ProcessGuid, source="amsi".
 *
 * JSON safety
 *   String values are JSON-escaped: \\ \" \n \r \t and any byte < 0x20.
 *   This is sufficient for all observed Sysmon field values (file paths,
 *   registry keys, command lines, SIDs).
 *
 * Field names
 *   Taken directly from the real Sysmon XML captured 2026-07-27 via
 *   Get-WinEvent | ToXml(). Names match the pySigma Sysmon pipeline
 *   field mappings used by pySigma-backend-sqlite.
 *   Source: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
 *
 * Caller contract
 *   json_out must be at least json_max bytes; json_max should be >= 4096
 *   for process-creation events (CommandLine can be long).
 *   Returns TRUE on success, FALSE if the buffer is too small or the XML
 *   is unparseable (missing EventID or Channel).
 */

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0602
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* EYXA_AMSI_EVENT is defined in amsi_reader.c (included before this file). */

/* ── meta structure returned alongside the JSON payload ─────────────── */
typedef struct {
    int   event_id;          /* from System/EventID; -1 if absent         */
    char  channel[128];      /* from System/Channel; UTF-8                */
    char  time_created[40];  /* from System/@SystemTime; ISO8601+Z        */
    char  source[16];        /* "sysmon" | "amsi" | "defender"            */
} EYXA_NORM_META;

/* ── private helpers ─────────────────────────────────────────────────── */

/*
 * Append len bytes from src into buf[*pos..buf_max].
 * Returns FALSE if the buffer is full.
 */
static BOOL buf_append(char *buf, size_t buf_max, size_t *pos,
                       const char *src, size_t len)
{
    if (*pos + len >= buf_max) return FALSE;
    memcpy(buf + *pos, src, len);
    *pos += len;
    buf[*pos] = '\0';
    return TRUE;
}

/* Append a null-terminated ASCII/UTF-8 string. */
static BOOL buf_str(char *buf, size_t buf_max, size_t *pos, const char *s)
{
    return buf_append(buf, buf_max, pos, s, strlen(s));
}

/*
 * JSON-escape a wide-char value and append it (including surrounding
 * double-quotes) to buf.
 */
static BOOL buf_json_wstr(char *buf, size_t buf_max, size_t *pos,
                           const WCHAR *wval, DWORD wval_len)
{
    /* Convert to UTF-8 first. */
    int needed = WideCharToMultiByte(CP_UTF8, 0, wval, (int)wval_len,
                                     NULL, 0, NULL, NULL);
    if (needed <= 0) {
        /* Empty or unconvertible - emit empty string. */
        return buf_str(buf, buf_max, pos, "\"\"");
    }
    char *utf8 = (char *)malloc((size_t)needed + 1);
    if (!utf8) return FALSE;
    WideCharToMultiByte(CP_UTF8, 0, wval, (int)wval_len,
                        utf8, needed, NULL, NULL);
    utf8[needed] = '\0';

    if (!buf_str(buf, buf_max, pos, "\"")) { free(utf8); return FALSE; }
    for (int i = 0; i < needed; i++) {
        unsigned char c = (unsigned char)utf8[i];
        char esc[8];
        const char *out = NULL;
        size_t out_len = 0;
        if      (c == '\\') { out = "\\\\"; out_len = 2; }
        else if (c == '"')  { out = "\\\""; out_len = 2; }
        else if (c == '\n') { out = "\\n";  out_len = 2; }
        else if (c == '\r') { out = "\\r";  out_len = 2; }
        else if (c == '\t') { out = "\\t";  out_len = 2; }
        else if (c < 0x20) {
            /* Control char - emit \uXXXX */
            _snprintf_s(esc, sizeof(esc), _TRUNCATE, "\\u%04x", c);
            out = esc; out_len = 6;
        } else {
            out = (const char *)&utf8[i]; out_len = 1;
        }
        if (!buf_append(buf, buf_max, pos, out, out_len)) {
            free(utf8); return FALSE;
        }
    }
    if (!buf_str(buf, buf_max, pos, "\"")) { free(utf8); return FALSE; }
    free(utf8);
    return TRUE;
}

/*
 * Extract a single-quoted XML attribute value.
 * Searches for attr='value' in xml and copies the value into out (UTF-8).
 * Returns length of value in out, or 0 on failure.
 *
 * EvtRender uses single quotes for all attributes (confirmed 2026-07-27).
 */
static DWORD xml_attr(const WCHAR *xml, const WCHAR *attr,
                       char *out, DWORD out_max)
{
    /* Build search pattern: attr=' */
    WCHAR pat[128];
    if (swprintf(pat, ARRAYSIZE(pat), L"%ls='", attr) < 0) return 0;

    const WCHAR *p = wcsstr(xml, pat);
    if (!p) return 0;
    p += wcslen(pat);
    const WCHAR *end = wcschr(p, L'\'');
    if (!end) return 0;
    DWORD wlen = (DWORD)(end - p);

    int n = WideCharToMultiByte(CP_UTF8, 0, p, (int)wlen,
                                out, (int)out_max - 1, NULL, NULL);
    if (n <= 0) return 0;
    out[n] = '\0';
    return (DWORD)n;
}

/*
 * Extract a simple element text value (between > and <).
 * Searches for <tag>value</tag>.
 * Returns a pointer into xml at the start of value, and sets *len.
 */
static const WCHAR *xml_element(const WCHAR *xml, const WCHAR *open_tag,
                                 DWORD *len)
{
    const WCHAR *p = wcsstr(xml, open_tag);
    if (!p) return NULL;
    p += wcslen(open_tag);
    const WCHAR *end = wcschr(p, L'<');
    if (!end) return NULL;
    *len = (DWORD)(end - p);
    return p;
}

/* ── public: Sysmon XML → JSON ──────────────────────────────────────── */

/*
 * Integer-value field names: emitted as JSON numbers, not strings.
 * Source: Sysmon EID 1 schema (ProcessId, ParentProcessId, TerminalSessionId).
 */
static BOOL is_integer_field(const WCHAR *name)
{
    /*
     * Fields emitted as JSON numbers so pySigma-backend-sqlite generates
     * correct numeric comparisons (json_extract(payload,'$.X') = N).
     *
     * Original set (Sysmon EID 1):
     *   ProcessId, ParentProcessId, TerminalSessionId, ScanResult
     *
     * Added for Security Event Log technique coverage:
     *   LogonType  – integer (2=Interactive,3=Network,10=RemoteInteractive)
     *                T1078, T1021.001/002, T1110
     *                Source: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
     *   KeyLength  – cipher key size in bits (0,128,256)
     *                T1078 logon events
     *                Source: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
     */
    return (wcscmp(name, L"ProcessId") == 0 ||
            wcscmp(name, L"ParentProcessId") == 0 ||
            wcscmp(name, L"TerminalSessionId") == 0 ||
            wcscmp(name, L"ScanResult") == 0 ||
            wcscmp(name, L"LogonType") == 0 ||
            wcscmp(name, L"KeyLength") == 0);
}

BOOL EyxaNormalizeSysmonXml(const WCHAR *xml,
                              char *json_out, DWORD json_max,
                              EYXA_NORM_META *meta)
{
    size_t pos = 0;
    DWORD  wlen;
    const WCHAR *p;

    if (!xml || !json_out || json_max < 64 || !meta) return FALSE;
    ZeroMemory(meta, sizeof(*meta));
    meta->event_id = -1;

    /* ── System section ─────────────────────────────────────────────── */

    /* EventID */
    p = xml_element(xml, L"<EventID>", &wlen);
    if (!p) return FALSE;
    {
        char id_str[16];
        int n = WideCharToMultiByte(CP_UTF8, 0, p, (int)wlen,
                                    id_str, (int)sizeof(id_str)-1, NULL, NULL);
        if (n > 0) { id_str[n] = '\0'; meta->event_id = atoi(id_str); }
    }

    /* Channel */
    p = xml_element(xml, L"<Channel>", &wlen);
    if (p) {
        WideCharToMultiByte(CP_UTF8, 0, p, (int)wlen,
                            meta->channel, (int)sizeof(meta->channel)-1,
                            NULL, NULL);
    }

    /* TimeCreated SystemTime='...' */
    xml_attr(xml, L"SystemTime", meta->time_created, sizeof(meta->time_created));

    /* source */
    strcpy_s(meta->source, sizeof(meta->source), "sysmon");

    /* ── Build JSON payload ──────────────────────────────────────────── */
    if (!buf_str(json_out, json_max, &pos, "{")) return FALSE;
    BOOL first = TRUE;

    /* Walk EventData <Data Name='field'>value</Data> entries. */
    const WCHAR *cursor = wcsstr(xml, L"<EventData>");
    if (!cursor) cursor = xml;

    while ((cursor = wcsstr(cursor, L"<Data Name='")) != NULL) {
        cursor += wcslen(L"<Data Name='");
        /* Extract field name (up to next single-quote). */
        const WCHAR *name_end = wcschr(cursor, L'\'');
        if (!name_end) break;
        DWORD name_len = (DWORD)(name_end - cursor);
        if (name_len == 0 || name_len > 127) { cursor = name_end + 1; continue; }

        WCHAR field_name[128];
        wcsncpy_s(field_name, ARRAYSIZE(field_name), cursor, name_len);
        field_name[name_len] = L'\0';

        /* Skip to > to find value start. */
        const WCHAR *gt = wcschr(name_end, L'>');
        if (!gt) break;
        gt++;

        /* Value ends at next < */
        const WCHAR *val_end = wcschr(gt, L'<');
        if (!val_end) break;
        DWORD val_len = (DWORD)(val_end - gt);

        /* Emit comma separator and key — save position so we can roll back
         * if the field name conversion fails (R-3 fix: old code emitted ","
         * and '"' then hit 'continue', leaving orphaned bytes in the buffer). */
        size_t pos_saved  = pos;
        BOOL   first_saved = first;

        if (!first && !buf_str(json_out, json_max, &pos, ",")) return FALSE;
        first = FALSE;

        /* Emit key (field name is always safe ASCII). */
        if (!buf_str(json_out, json_max, &pos, "\"")) return FALSE;
        {
            char fn_utf8[128];
            int n = WideCharToMultiByte(CP_UTF8, 0, field_name, -1,
                                        fn_utf8, (int)sizeof(fn_utf8)-1, NULL, NULL);
            if (n <= 0) return FALSE;
            /* WideCharToMultiByte with -1 returns count *including* NUL terminator.
             * Set fn_utf8[n-1]=NUL to trim it. n==1 means empty output - roll back. */
            if (n < 2) { pos = pos_saved; first = first_saved; cursor = val_end + 1; continue; }
            fn_utf8[n-1] = '\0';
            if (!buf_str(json_out, json_max, &pos, fn_utf8)) return FALSE;
        }
        if (!buf_str(json_out, json_max, &pos, "\":")) return FALSE;

        /* Emit value. */
        if (is_integer_field(field_name) && val_len > 0 && val_len < 20) {
            /* Emit as JSON number. */
            char num[24];
            int n = WideCharToMultiByte(CP_UTF8, 0, gt, (int)val_len,
                                        num, (int)sizeof(num)-1, NULL, NULL);
            /* C-3 fix: check buf_str return — a silent drop here produces
             * truncated JSON like "ProcessId":  with no value → HTTP 400. */
            if (n > 0) { num[n] = '\0'; if (!buf_str(json_out, json_max, &pos, num)) return FALSE; }
            else       { if (!buf_str(json_out, json_max, &pos, "0")) return FALSE; }
        } else {
            if (!buf_json_wstr(json_out, json_max, &pos, gt, val_len)) return FALSE;
        }

        cursor = val_end + 1;
    }

    /* Append __raw__ containing the original XML for events.raw_json. */
    if (!first && !buf_str(json_out, json_max, &pos, ",")) return FALSE;
    if (!buf_str(json_out, json_max, &pos, "\"__raw__\":")) return FALSE;
    if (!buf_json_wstr(json_out, json_max, &pos, xml, (DWORD)wcslen(xml)))
        return FALSE;

    if (!buf_str(json_out, json_max, &pos, "}")) return FALSE;
    return TRUE;
}

/* ── public: AMSI event → JSON ──────────────────────────────────────── */

BOOL EyxaNormalizeAmsiEvent(const EYXA_AMSI_EVENT *ev,
                             char *json_out, DWORD json_max,
                             EYXA_NORM_META *meta)
{
    size_t pos = 0;
    char   tmp[64];

    if (!ev || !json_out || json_max < 256 || !meta) return FALSE;
    ZeroMemory(meta, sizeof(*meta));

    meta->event_id = 1101;  /* Microsoft-Antimalware-Scan-Interface EID 1101 */
    strcpy_s(meta->channel, sizeof(meta->channel),
             "Microsoft-Antimalware-Scan-Interface");
    /* TimeCreated from FILETIME (100ns intervals since 1601-01-01). */
    {
        FILETIME ft;
        ft.dwLowDateTime  = (DWORD)(ev->timestamp_filetime & 0xFFFFFFFF);
        ft.dwHighDateTime = (DWORD)(ev->timestamp_filetime >> 32);
        SYSTEMTIME st;
        FileTimeToSystemTime(&ft, &st);
        _snprintf_s(meta->time_created, sizeof(meta->time_created), _TRUNCATE,
                  "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                  st.wYear, st.wMonth, st.wDay,
                  st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    }
    strcpy_s(meta->source, sizeof(meta->source), "amsi");

    if (!buf_str(json_out, json_max, &pos, "{")) return FALSE;

    /* ContentName */
    if (!buf_str(json_out, json_max, &pos, "\"ContentName\":")) return FALSE;
    if (!buf_json_wstr(json_out, json_max, &pos,
                       ev->content_name, (DWORD)wcslen(ev->content_name)))
        return FALSE;

    /* ProcessGuid */
    if (!buf_str(json_out, json_max, &pos, ",\"ProcessGuid\":")) return FALSE;
    if (!buf_json_wstr(json_out, json_max, &pos,
                       ev->process_guid, (DWORD)wcslen(ev->process_guid)))
        return FALSE;

    /* ProcessId */
    _snprintf_s(tmp, sizeof(tmp), _TRUNCATE, ",\"ProcessId\":%lu", ev->pid);
    if (!buf_str(json_out, json_max, &pos, tmp)) return FALSE;

    /* ScanResult */
    _snprintf_s(tmp, sizeof(tmp), _TRUNCATE, ",\"ScanResult\":%lu", ev->scan_result);
    if (!buf_str(json_out, json_max, &pos, tmp)) return FALSE;

    /* Content (raw scan buffer, truncated at 65536 bytes). */
    if (!buf_str(json_out, json_max, &pos, ",\"Content\":")) return FALSE;
    if (ev->content_size > 0) {
        DWORD cbytes = ev->content_size < 65536 ? ev->content_size : 65536;
        /* Treat content as wide chars if length is even. */
        if (cbytes % 2 == 0) {
            if (!buf_json_wstr(json_out, json_max, &pos,
                               (const WCHAR *)ev->content, cbytes / sizeof(WCHAR)))
                return FALSE;
        } else {
            /* Fallback: emit as hex string. */
            if (!buf_str(json_out, json_max, &pos, "\"<binary>\"")) return FALSE;
        }
    } else {
        if (!buf_str(json_out, json_max, &pos, "\"\"")) return FALSE;
    }

    if (!buf_str(json_out, json_max, &pos, "}")) return FALSE;
    return TRUE;
}

#endif /* EYXA_NORMALIZER_C */
