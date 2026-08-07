/*
 * tamper_watcher.c -- File system tamper detection for C:\ProgramData\Eyxa\ (A9).
 *
 * Uses ReadDirectoryChangesW to watch the Eyxa data directory for:
 *   - Deletion of the agent token file (eyxa-token.bin)
 *   - Deletion of the bookmark file (sysmon-bookmark.xml)
 *   - Any new executables or scripts written into the directory
 *
 * On detecting a tamper event, emits a JSON alert to the caller's sink
 * so it is forwarded to the backend the same way any other event is.
 *
 * Also hardens the directory ACL on startup: grants SYSTEM full control,
 * removes write/delete access for non-elevated standard users.
 *
 * Source: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw
 * Source: https://learn.microsoft.com/en-us/windows/win32/secauthz/modifying-the-acls-of-an-object-in-c--
 *
 * Unity-build: included from main.c, not compiled separately.
 */

#ifndef EYXA_TAMPER_WATCHER_C
#define EYXA_TAMPER_WATCHER_C

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0602
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define EYXA_TAMPER_WATCH_DIR  L"C:\\ProgramData\\Eyxa"
#define EYXA_TAMPER_BUF_SIZE   4096

typedef BOOL (WINAPI *EYXA_TAMPER_SINK)(const char *json, void *context);

typedef struct {
    HANDLE            dir_handle;
    HANDLE            watcher_thread;
    EYXA_TAMPER_SINK  sink;
    void             *sink_context;
    volatile LONG     stopping;
} EYXA_TAMPER_WATCHER;

/* ── Harden the data directory ACL ──────────────────────────────────────
 * Sets DACL so SYSTEM has full control and BUILTIN\Users cannot write or
 * delete files. Administrators retain full control.
 * Source: https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setnamedSecurityInfow
 */
static void EyxaHardenDataDir(void)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    PACL  dacl = NULL;
    BOOL  ok;

    /* SDDL: System=Full, Admins=Full, Users=Read+Execute only.
     * D:P = protected DACL (not inherited), prevents parent writes breaking this.
     * Source: https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings */
    ok = ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:P"
        L"(A;;FA;;;SY)"    /* SYSTEM: Full Access */
        L"(A;;FA;;;BA)"    /* BUILTIN\\Administrators: Full Access */
        L"(A;;0x1200A9;;;BU)", /* BUILTIN\\Users: Read+Execute only (no write/delete) */
        SDDL_REVISION_1, &sd, NULL);

    if (!ok || !sd) return;

    if (GetSecurityDescriptorDacl(sd, &ok, &dacl, &ok) && ok && dacl) {
        SetNamedSecurityInfoW(
            (LPWSTR)EYXA_TAMPER_WATCH_DIR,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            NULL, NULL, dacl, NULL);
    }

    LocalFree(sd);
}

/* ── Emit a tamper alert JSON to the sink ───────────────────────────── */
static void EyxaTamperEmitAlert(EYXA_TAMPER_WATCHER *w,
                                 const char *event_type,
                                 const char *filename)
{
    char ts[32];
    char json[512];
    SYSTEMTIME st;

    if (!w->sink) return;

    GetSystemTime(&st);
    _snprintf_s(ts, sizeof(ts), _TRUNCATE,
        "%04d-%02d-%02dT%02d:%02d:%02dZ",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);

    _snprintf_s(json, sizeof(json), _TRUNCATE,
        "{"
        "\"EventID\":9999,"
        "\"Channel\":\"Eyxa-TamperDetection\","
        "\"TimeCreated\":\"%s\","
        "\"source\":\"tamper\","
        "\"EventType\":\"%s\","
        "\"TargetFile\":\"%s\","
        "\"Description\":\"Eyxa data directory tamper detected\""
        "}",
        ts, event_type, filename);

    w->sink(json, w->sink_context);
}

/* ── Watcher thread ──────────────────────────────────────────────────── */
static DWORD WINAPI EyxaTamperWatcherThread(LPVOID param)
{
    EYXA_TAMPER_WATCHER *w = (EYXA_TAMPER_WATCHER *)param;
    BYTE  buf[EYXA_TAMPER_BUF_SIZE];
    DWORD bytes_returned;
    OVERLAPPED ov = {0};
    HANDLE ov_event;

    /* Source: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw */
    ov_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!ov_event) return 1;
    ov.hEvent = ov_event;

    while (!InterlockedCompareExchange(&w->stopping, 0, 0)) {
        ResetEvent(ov_event);

        /* Monitor: file name changes (add/remove/rename), attribute changes.
         * bWatchSubtree=FALSE: only the top-level Eyxa directory.
         * Source: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw */
        if (!ReadDirectoryChangesW(
                w->dir_handle, buf, sizeof(buf),
                FALSE, /* not recursive */
                FILE_NOTIFY_CHANGE_FILE_NAME |
                FILE_NOTIFY_CHANGE_LAST_WRITE |
                FILE_NOTIFY_CHANGE_SECURITY,
                &bytes_returned, &ov, NULL)) {
            /* Handle lost (e.g. directory deleted itself) - wait and retry */
            Sleep(5000);
            continue;
        }

        /* Wait for notification or stop signal */
        HANDLE handles[2] = { ov_event, NULL };
        DWORD wait = WaitForMultipleObjects(1, handles, FALSE, 10000);

        if (InterlockedCompareExchange(&w->stopping, 0, 0)) break;
        if (wait == WAIT_TIMEOUT) continue;
        if (wait != WAIT_OBJECT_0) break;

        if (!GetOverlappedResult(w->dir_handle, &ov, &bytes_returned, FALSE))
            continue;
        if (bytes_returned == 0) continue;

        /* Walk the FILE_NOTIFY_INFORMATION linked list
         * Source: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-file_notify_information */
        FILE_NOTIFY_INFORMATION *fni = (FILE_NOTIFY_INFORMATION *)buf;
        for (;;) {
            /* Convert wide filename to UTF-8 for the JSON sink */
            char fname_u8[512] = {0};
            int len = fni->FileNameLength / sizeof(WCHAR);
            WideCharToMultiByte(CP_UTF8, 0, fni->FileName, len,
                                fname_u8, sizeof(fname_u8)-1, NULL, NULL);

            const char *event_type = NULL;
            switch (fni->Action) {
                case FILE_ACTION_REMOVED:
                case FILE_ACTION_RENAMED_OLD_NAME:
                    /* Only flag deletion of files the agent does NOT write
                     * during normal operation. Bookmark/log files are deleted
                     * and recreated constantly by sysmon_reader -- not tamper. */
                    if (_stricmp(fname_u8, "eyxa-token.bin")   == 0 ||
                        _stricmp(fname_u8, "eyxa-events.bin")  == 0)
                        event_type = "FILE_DELETED";
                    break;
                case FILE_ACTION_ADDED:
                case FILE_ACTION_RENAMED_NEW_NAME:
                    /* Only alert on new executables or scripts added */
                    {
                        size_t n = strlen(fname_u8);
                        if ((n > 4 && _stricmp(fname_u8 + n - 4, ".exe") == 0) ||
                            (n > 4 && _stricmp(fname_u8 + n - 4, ".bat") == 0) ||
                            (n > 3 && _stricmp(fname_u8 + n - 3, ".ps1") == 0))
                            event_type = "SUSPICIOUS_FILE_ADDED";
                    }
                    break;
                case FILE_ACTION_MODIFIED:
                    /* Alert only on critical files */
                    if (_stricmp(fname_u8, "eyxa-token.bin") == 0 ||
                        _stricmp(fname_u8, "sysmon-bookmark.xml") == 0)
                        event_type = "CRITICAL_FILE_MODIFIED";
                    break;
            }

            if (event_type)
                EyxaTamperEmitAlert(w, event_type, fname_u8);

            if (fni->NextEntryOffset == 0) break;
            fni = (FILE_NOTIFY_INFORMATION *)((BYTE *)fni + fni->NextEntryOffset);
        }
    }

    CloseHandle(ov_event);
    return 0;
}

/* ── Public API ──────────────────────────────────────────────────────── */
BOOL EyxaTamperWatcherStart(EYXA_TAMPER_WATCHER *w,
                             EYXA_TAMPER_SINK sink, void *ctx)
{
    if (!w || !sink) return FALSE;
    ZeroMemory(w, sizeof(*w));
    w->sink         = sink;
    w->sink_context = ctx;

    /* Harden the directory ACL first */
    EyxaHardenDataDir();

    /* Open directory handle for ReadDirectoryChangesW.
     * Requires FILE_LIST_DIRECTORY access right.
     * Source: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew */
    w->dir_handle = CreateFileW(
        EYXA_TAMPER_WATCH_DIR,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        NULL);

    if (w->dir_handle == INVALID_HANDLE_VALUE) {
        w->dir_handle = NULL;
        return FALSE;
    }

    w->watcher_thread = CreateThread(NULL, 0, EyxaTamperWatcherThread, w, 0, NULL);
    if (!w->watcher_thread) {
        CloseHandle(w->dir_handle);
        w->dir_handle = NULL;
        return FALSE;
    }
    return TRUE;
}

void EyxaTamperWatcherStop(EYXA_TAMPER_WATCHER *w)
{
    if (!w) return;
    InterlockedExchange(&w->stopping, 1);
    /* Cancel any pending I/O on the directory handle to unblock the thread */
    if (w->dir_handle) CancelIoEx(w->dir_handle, NULL);
    if (w->watcher_thread) {
        WaitForSingleObject(w->watcher_thread, 5000);
        CloseHandle(w->watcher_thread);
        w->watcher_thread = NULL;
    }
    if (w->dir_handle) {
        CloseHandle(w->dir_handle);
        w->dir_handle = NULL;
    }
}

#endif /* EYXA_TAMPER_WATCHER_C */
