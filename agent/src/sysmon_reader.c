/*
 * Eyxa Sysmon reader -- Phase 3 module 1, expanded Phase B (Expansion).
 *
 * Subscribes to ALL Sysmon events (XPath: "*") via EvtSubscribe.
 * Sysmon itself determines which EIDs to generate via sysmon_config.xml;
 * the agent applies no additional XPath filter so adding a new EID requires
 * only a Sysmon config reload - zero code changes in this file.
 *
 * Renders events as XML and resumes from an atomically persisted bookmark.
 * The caller's sink must return TRUE only after it durably accepts an event;
 * this module advances its bookmark only after that acknowledgement.
 *
 * Design decision (Option A, approved 2026-07-29): subscribe with L"*" rather
 * than parsing sysmon_config.xml's complex <ProcessCreate>/<NetworkConnect>/...
 * schema. Sysmon's own config is the authoritative filter.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winevt.h>
#include <shlobj.h>
#include <knownfolders.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#define EYXA_SYSMON_CHANNEL L"Microsoft-Windows-Sysmon/Operational"
/* Subscribe to ALL Sysmon events; Sysmon config determines what is generated.
 * Source: https://learn.microsoft.com/en-us/windows/win32/wes/consuming-events#xpath-10-queries */
#define EYXA_SYSMON_QUERY   L"*"
#define EYXA_STATE_DIR_NAME     L"Eyxa"
#define EYXA_BOOKMARK_FILE_NAME L"sysmon-bookmark.xml"

typedef BOOL (WINAPI *EYXA_EVENT_SINK)(const WCHAR *channel,
                                       const WCHAR *event_xml,
                                       void *context);

typedef struct {
    EVT_HANDLE subscription;
    EVT_HANDLE bookmark;
    EYXA_EVENT_SINK sink;
    void *sink_context;
    WCHAR bookmark_path[MAX_PATH];
    volatile LONG stopping;
    volatile LONG callbacks_inflight;
    volatile LONG failed;
    DWORD last_error;
} EYXA_SYSMON_READER;

static BOOL EyxaRenderXml(EVT_HANDLE handle, EVT_RENDER_FLAGS flag,
                          WCHAR **xml_out)
{
    DWORD used = 0, property_count = 0;
    WCHAR *xml;

    if (xml_out == NULL) return FALSE;
    *xml_out = NULL;

    if (EvtRender(NULL, handle, flag, 0, NULL, &used, &property_count) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER || used == 0)
        return FALSE;

    xml = (WCHAR *)calloc(1, used + sizeof(WCHAR));
    if (xml == NULL) return FALSE;

    if (!EvtRender(NULL, handle, flag, used, xml, &used, &property_count)) {
        free(xml);
        return FALSE;
    }

    *xml_out = xml;
    return TRUE;
}

static BOOL EyxaWriteBookmarkAtomically(const WCHAR *path, const WCHAR *xml)
{
    WCHAR temp_path[MAX_PATH];
    HANDLE file = INVALID_HANDLE_VALUE;
    DWORD bytes = 0;
    size_t chars;
    BOOL ok = FALSE;

    if (path == NULL || xml == NULL) return FALSE;
    if (swprintf(temp_path, MAX_PATH, L"%ls.tmp", path) < 0) return FALSE;

    file = CreateFileW(temp_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;

    chars = wcslen(xml);
    if (chars > (MAXDWORD / sizeof(WCHAR))) goto done;
    if (!WriteFile(file, xml, (DWORD)(chars * sizeof(WCHAR)), &bytes, NULL) ||
        bytes != chars * sizeof(WCHAR) || !FlushFileBuffers(file))
        goto done;

    CloseHandle(file);
    file = INVALID_HANDLE_VALUE;
    if (!MoveFileExW(temp_path, path,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(temp_path); /* M-1 fix: clean up orphaned .tmp on rename failure */
        return FALSE;
    }
    return TRUE;

done:
    CloseHandle(file);
    DeleteFileW(temp_path);
    return ok;
}

static BOOL EyxaLoadBookmark(const WCHAR *path, EVT_HANDLE *bookmark_out)
{
    HANDLE file = INVALID_HANDLE_VALUE;
    LARGE_INTEGER size;
    DWORD read = 0;
    WCHAR *xml = NULL;
    EVT_HANDLE bookmark = NULL;
    BOOL ok = FALSE;

    if (bookmark_out == NULL) return FALSE;
    *bookmark_out = NULL;

    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return GetLastError() == ERROR_FILE_NOT_FOUND;
    }
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
        size.QuadPart > 1024 * 1024 || (size.QuadPart % sizeof(WCHAR)) != 0)
        goto done;

    xml = (WCHAR *)calloc(1, (size_t)size.QuadPart + sizeof(WCHAR));
    if (xml == NULL) goto done;
    if (!ReadFile(file, xml, (DWORD)size.QuadPart, &read, NULL) ||
        read != (DWORD)size.QuadPart)
        goto done;

    bookmark = EvtCreateBookmark(xml);
    if (bookmark == NULL) {
        /* Corrupt/partial XML from a dirty shutdown (force-kill mid-write).
         * Delete the bad file so the next start is clean, then return TRUE
         * with *bookmark_out=NULL so the caller subscribes from "now".
         * Same recovery pattern as stale-bookmark handling in EyxaSysmonReaderStart.
         * Source: https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtcreatebookmark */
        free(xml); xml = NULL;
        CloseHandle(file); file = INVALID_HANDLE_VALUE;
        DeleteFileW(path);
        return TRUE;  /* *bookmark_out already NULL - subscribe from now */
    }
    *bookmark_out = bookmark;
    bookmark = NULL;
    ok = TRUE;

done:
    if (bookmark != NULL) EvtClose(bookmark);
    free(xml);
    CloseHandle(file);
    return ok;
}

static BOOL EyxaBuildBookmarkPath(WCHAR *path, DWORD path_chars)
{
    PWSTR program_data = NULL;
    WCHAR state_dir[MAX_PATH];
    HRESULT hr;
    BOOL ok = FALSE;

    if (path == NULL || path_chars == 0) return FALSE;
    hr = SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, NULL, &program_data);
    if (FAILED(hr) || program_data == NULL) return FALSE;

    if (swprintf(state_dir, MAX_PATH, L"%ls\\%ls", program_data,
                 EYXA_STATE_DIR_NAME) < 0)
        goto done;
    if (!CreateDirectoryW(state_dir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
        goto done;
    if (swprintf(path, path_chars, L"%ls\\%ls", state_dir,
                 EYXA_BOOKMARK_FILE_NAME) < 0)
        goto done;
    ok = TRUE;

done:
    CoTaskMemFree(program_data);
    return ok;
}

static DWORD WINAPI EyxaSysmonCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action,
                                        PVOID context, EVT_HANDLE event)
{
    EYXA_SYSMON_READER *reader = (EYXA_SYSMON_READER *)context;
    WCHAR *event_xml = NULL;
    WCHAR *bookmark_xml = NULL;

    if (reader == NULL)
        return ERROR_SUCCESS;

    InterlockedIncrement(&reader->callbacks_inflight);
    if (InterlockedCompareExchange(&reader->stopping, 0, 0))
        goto done;

    if (action == EvtSubscribeActionError) {
        DWORD err = (DWORD)(ULONG_PTR)event;
        reader->last_error = err;
        if (err == ERROR_EVT_QUERY_RESULT_STALE) {
            DeleteFileW(reader->bookmark_path);
        }
        InterlockedExchange(&reader->failed, 1);
        goto done;
    }
    if (action != EvtSubscribeActionDeliver) goto done;

    if (!EyxaRenderXml(event, EvtRenderEventXml, &event_xml) ||
        reader->sink == NULL ||
        !reader->sink(EYXA_SYSMON_CHANNEL, event_xml, reader->sink_context)) {
        /* Drop the event but do not permanently fail the module. */
        goto done;
    }

    if (!EvtUpdateBookmark(reader->bookmark, event) ||
        !EyxaRenderXml(reader->bookmark, EvtRenderBookmark, &bookmark_xml) ||
        !EyxaWriteBookmarkAtomically(reader->bookmark_path, bookmark_xml)) {
        /* H-1 fix: bookmark write is best-effort. A transient disk error (e.g.
         * AV scanner locking the file) must NOT permanently kill event collection.
         * Worst-case on crash/restart: re-read the last few events (at-least-once).
         * Record the error code for diagnostics but do NOT set failed=1. */
        reader->last_error = GetLastError();
    }

done:
    free(bookmark_xml);
    free(event_xml);
    InterlockedDecrement(&reader->callbacks_inflight);
    return ERROR_SUCCESS;
}

BOOL EyxaSysmonReaderStart(EYXA_SYSMON_READER *reader,
                           EYXA_EVENT_SINK sink, void *sink_context)
{
    DWORD flags;
    BOOL resuming;

    if (reader == NULL || sink == NULL) return FALSE;
    ZeroMemory(reader, sizeof(*reader));
    reader->sink = sink;
    reader->sink_context = sink_context;

    if (!EyxaBuildBookmarkPath(reader->bookmark_path, MAX_PATH) ||
        !EyxaLoadBookmark(reader->bookmark_path, &reader->bookmark))
        return FALSE;

    resuming = reader->bookmark != NULL;
    if (!resuming) {
        reader->bookmark = EvtCreateBookmark(NULL);
        if (reader->bookmark == NULL) {
            reader->last_error = GetLastError();
            return FALSE;
        }
    }

    flags = resuming
        ? EvtSubscribeStartAfterBookmark | EvtSubscribeStrict
        : EvtSubscribeToFutureEvents;
    reader->subscription = EvtSubscribe(NULL, NULL, EYXA_SYSMON_CHANNEL,
                                        EYXA_SYSMON_QUERY,
                                        resuming ? reader->bookmark : NULL,
                                        reader, EyxaSysmonCallback, flags);
    if (reader->subscription == NULL) {
        DWORD err = GetLastError();
        /* ERROR_EVT_QUERY_RESULT_STALE (15011 / 0x3AA3): the event log
         * wrapped (rotated) while the agent was offline and overwrote the
         * bookmarked record.  Recovery: delete the stale bookmark file and
         * resume from the newest event.  The coverage gap is logged as WARN.
         * Source: https://learn.microsoft.com/en-us/windows/win32/wes/
         *         windows-event-log-error-constants */
        if (err == ERROR_EVT_QUERY_RESULT_STALE && resuming) {
            /* Close the stale bookmark handle */
            if (reader->bookmark != NULL) {
                EvtClose(reader->bookmark);
                reader->bookmark = NULL;
            }
            /* Delete the stale bookmark file so the next start is clean */
            DeleteFileW(reader->bookmark_path);

            /* Create a fresh empty bookmark and subscribe from "now" */
            reader->bookmark = EvtCreateBookmark(NULL);
            if (reader->bookmark == NULL) {
                reader->last_error = GetLastError();
                return FALSE;
            }
            reader->subscription = EvtSubscribe(
                NULL, NULL, EYXA_SYSMON_CHANNEL,
                EYXA_SYSMON_QUERY, NULL,
                reader, EyxaSysmonCallback,
                EvtSubscribeToFutureEvents);
            if (reader->subscription != NULL) {
                /* Successfully recovered -- caller should log the gap warning */
                reader->last_error = ERROR_EVT_QUERY_RESULT_STALE;
                return TRUE; /* last_error set to STALE as gap signal */
            }
        }
        reader->last_error = GetLastError();
        if (reader->bookmark != NULL) EvtClose(reader->bookmark);
        reader->bookmark = NULL;
        return FALSE;
    }
    return TRUE;
}

void EyxaSysmonReaderStop(EYXA_SYSMON_READER *reader)
{
    if (reader == NULL) return;
    InterlockedExchange(&reader->stopping, 1);
    if (reader->subscription != NULL) EvtClose(reader->subscription);
    while (InterlockedCompareExchange(&reader->callbacks_inflight, 0, 0) != 0)
        Sleep(1);
    if (reader->bookmark != NULL) EvtClose(reader->bookmark);
    reader->subscription = NULL;
    reader->bookmark = NULL;
}

BOOL EyxaSysmonReaderFailed(const EYXA_SYSMON_READER *reader,
                            DWORD *last_error_out)
{
    if (reader == NULL) return TRUE;
    if (last_error_out != NULL) *last_error_out = reader->last_error;
    return InterlockedCompareExchange((volatile LONG *)&reader->failed, 0, 0) != 0;
}
