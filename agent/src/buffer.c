#ifndef EYXA_BUFFER_C
#define EYXA_BUFFER_C
/*
 * Eyxa local durable event buffer -- Phase 3 module 3.
 *
 * Appends variable-length records to an on-disk append log persisted in
 * ProgramData\Eyxa\eyxa-events.bin.  A companion cursor file
 * (eyxa-cursor.bin) tracks the byte offset through which the sender has
 * successfully flushed; all bytes from the cursor to EOF are pending.
 *
 * Crash safety
 * ── Every append is followed by FlushFileBuffers so data survives a
 *    process crash.  The cursor is updated atomically (write to a .tmp
 *    file then rename over the real cursor file with
 *    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH).  On restart
 *    the module reopens the existing log and resumes from the last
 *    committed cursor position, so events buffered before a crash are
 *    retransmitted exactly once.
 *
 * Overflow
 * ── When uncommitted bytes would exceed EYXA_BUFFER_MAX_PENDING the
 *    append is refused and the overflow counter is incremented.  This
 *    makes data loss observable rather than silent.
 *
 * Thread safety
 * ── A single CRITICAL_SECTION serialises every file operation.
 *
 * Caller contract
 * ── Call EyxaBufferOpen once (succeeds only as Administrator / SYSTEM
 *    because it creates ProgramData\Eyxa\).
 * ── Pass every EYXA_BUFFER_BATCH* returned by EyxaBufferReadBatch to
 *    EyxaBufferBatchFree regardless of whether EyxaBufferCommit was
 *    called.
 * ── Do not call any other function after EyxaBufferClose.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#include <knownfolders.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── tunables ──────────────────────────────────────────────────────── */
#define EYXA_BUFFER_MAGIC       0xEA1A1A1AUL
#define EYXA_BUFFER_MAX_PENDING (64UL * 1024UL * 1024UL)  /* 64 MB   */
#define EYXA_BATCH_MAX_READ     (4UL  * 1024UL * 1024UL)  /* 4 MB    */
#define EYXA_BATCH_MAX_RECORDS  1000UL
#define EYXA_STATE_DIR_NAME     L"Eyxa"
#define EYXA_EVENTS_FILE_NAME   L"eyxa-events.bin"
#define EYXA_CURSOR_FILE_NAME   L"eyxa-cursor.bin"

/* ── on-disk layout ────────────────────────────────────────────────── */

/*
 * Every record on disk is:
 *   [EYXA_RECORD_HDR][payload bytes]
 * The payload is whatever the caller passes to EyxaBufferAppend.
 * The magic guards against reading a partially-written or corrupt log.
 */
#pragma pack(push, 1)
typedef struct {
    DWORD magic;        /* must equal EYXA_BUFFER_MAGIC */
    DWORD payload_len;  /* byte count of the payload that follows */
} EYXA_RECORD_HDR;
#pragma pack(pop)

/* ── public types ──────────────────────────────────────────────────── */

/*
 * Heap-allocated batch returned by EyxaBufferReadBatch.
 *
 * The `data` array holds all records serialised as:
 *   [DWORD payload_len][BYTE payload[payload_len]] ...
 * (the on-disk magic header is stripped; callers see only payload lengths).
 *
 * Workflow:
 *   batch = EyxaBufferReadBatch(...);
 *   if (batch) {
 *       // send batch->data to backend
 *       EyxaBufferCommit(buf, batch->end_offset);
 *       EyxaBufferBatchFree(batch);
 *   }
 */
typedef struct {
    UINT64 end_offset;    /* pass to EyxaBufferCommit on successful send */
    DWORD  record_count;
    DWORD  data_bytes;    /* total bytes in data[], including length prefixes */
    BYTE   data[1];       /* flexible; allocated with calloc */
} EYXA_BUFFER_BATCH;

typedef struct {
    HANDLE           log;
    CRITICAL_SECTION lock;
    WCHAR            log_path[MAX_PATH];
    WCHAR            cursor_path[MAX_PATH];
    UINT64           write_pos;     /* next byte to write (monotonically increasing) */
    UINT64           commit_pos;    /* last committed cursor byte offset             */
    volatile LONG    overflow_count;
} EYXA_BUFFER;

/* ── private helpers ───────────────────────────────────────────────── */

static BOOL EyxaBuildBufferPaths(EYXA_BUFFER *b)
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
    if (swprintf(b->log_path, MAX_PATH, L"%ls\\%ls",
                 state_dir, EYXA_EVENTS_FILE_NAME) < 0) goto done;
    if (swprintf(b->cursor_path, MAX_PATH, L"%ls\\%ls",
                 state_dir, EYXA_CURSOR_FILE_NAME) < 0) goto done;
    ok = TRUE;
done:
    CoTaskMemFree(program_data);
    return ok;
}

static BOOL EyxaLoadCursor(const WCHAR *path, UINT64 *pos_out)
{
    HANDLE f;
    DWORD  read = 0;
    BOOL   ok;

    *pos_out = 0;
    f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
        return GetLastError() == ERROR_FILE_NOT_FOUND; /* first run: OK */
    ok = ReadFile(f, pos_out, (DWORD)sizeof(*pos_out), &read, NULL) &&
         read == (DWORD)sizeof(*pos_out);
    CloseHandle(f);
    return ok;
}

static BOOL EyxaWriteCursorAtomically(const WCHAR *path, UINT64 pos)
{
    WCHAR  tmp[MAX_PATH];
    HANDLE f = INVALID_HANDLE_VALUE;
    DWORD  written = 0;
    BOOL   ok = FALSE;

    if (swprintf(tmp, MAX_PATH, L"%ls.tmp", path) < 0) return FALSE;
    f = CreateFileW(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return FALSE;
    if (!WriteFile(f, &pos, (DWORD)sizeof(pos), &written, NULL) ||
        written != (DWORD)sizeof(pos) || !FlushFileBuffers(f))
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

/*
 * Reset both files to empty once everything has been sent.
 * Called under the lock; caller must verify commit_pos == write_pos > 0.
 */
static void EyxaTrimLog(EYXA_BUFFER *b)
{
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    if (SetFilePointerEx(b->log, zero, NULL, FILE_BEGIN))
        SetEndOfFile(b->log);
    EyxaWriteCursorAtomically(b->cursor_path, 0ULL);
    b->write_pos  = 0;
    b->commit_pos = 0;
}

/* ── public API ────────────────────────────────────────────────────── */

BOOL EyxaBufferOpen(EYXA_BUFFER *b)
{
    LARGE_INTEGER size;

    if (b == NULL) return FALSE;
    ZeroMemory(b, sizeof(*b));
    b->log = INVALID_HANDLE_VALUE;
    InitializeCriticalSection(&b->lock);

    if (!EyxaBuildBufferPaths(b)) goto fail;
    if (!EyxaLoadCursor(b->cursor_path, &b->commit_pos)) goto fail;

    b->log = CreateFileW(b->log_path,
                         GENERIC_READ | GENERIC_WRITE,
                         /* P-3 fix: FILE_SHARE_READ allows AV scanners to open
                          * the file concurrently without ERROR_SHARING_VIOLATION.
                          * All writes are serialised by the CRITICAL_SECTION.
                          * FILE_SHARE_WRITE is not set -- no other writer expected.
                          * Source: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew */
                         FILE_SHARE_READ,
                         NULL, OPEN_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
                         NULL);


    if (b->log == INVALID_HANDLE_VALUE) goto fail;

    if (!GetFileSizeEx(b->log, &size)) goto fail;
    b->write_pos = (UINT64)size.QuadPart;

    /* Guard: cursor must never exceed the actual log EOF. */
    if (b->commit_pos > b->write_pos)
        b->commit_pos = b->write_pos;

    return TRUE;
fail:
    if (b->log != INVALID_HANDLE_VALUE) {
        CloseHandle(b->log);
        b->log = INVALID_HANDLE_VALUE;
    }
    DeleteCriticalSection(&b->lock);
    return FALSE;
}

void EyxaBufferClose(EYXA_BUFFER *b)
{
    if (b == NULL) return;
    if (b->log != INVALID_HANDLE_VALUE) {
        CloseHandle(b->log);
        b->log = INVALID_HANDLE_VALUE;
    }
    DeleteCriticalSection(&b->lock);
}

/*
 * Append one record to the log.
 * Returns FALSE and increments the overflow counter when the uncommitted
 * backlog would exceed EYXA_BUFFER_MAX_PENDING; otherwise returns FALSE
 * only on a genuine I/O error (the counter is NOT incremented in that case).
 */
BOOL EyxaBufferAppend(EYXA_BUFFER *b, const void *data, DWORD len)
{
    EYXA_RECORD_HDR hdr;
    LARGE_INTEGER   seek;
    DWORD           written = 0;
    BOOL            ok = FALSE;

    if (b == NULL || data == NULL || len == 0) return FALSE;

    EnterCriticalSection(&b->lock);

    if ((b->write_pos - b->commit_pos) + sizeof(hdr) + len >
        EYXA_BUFFER_MAX_PENDING) {
        InterlockedIncrement(&b->overflow_count);
        goto done;
    }

    seek.QuadPart = (LONGLONG)b->write_pos;
    if (!SetFilePointerEx(b->log, seek, NULL, FILE_BEGIN)) goto done;

    hdr.magic       = EYXA_BUFFER_MAGIC;
    hdr.payload_len = len;

    if (!WriteFile(b->log, &hdr, (DWORD)sizeof(hdr), &written, NULL) ||
        written != (DWORD)sizeof(hdr))
        goto done;
    if (!WriteFile(b->log, data, len, &written, NULL) || written != len)
        goto done;
    if (!FlushFileBuffers(b->log)) goto done;

    b->write_pos += (UINT64)(sizeof(hdr) + len);
    ok = TRUE;
done:
    LeaveCriticalSection(&b->lock);
    return ok;
}

/*
 * Read up to max_records pending records (starting at commit_pos) into a
 * heap-allocated EYXA_BUFFER_BATCH.  Returns NULL if there is nothing
 * pending or on OOM / I/O error.
 * The caller must call EyxaBufferBatchFree unconditionally when done.
 */
EYXA_BUFFER_BATCH *EyxaBufferReadBatch(EYXA_BUFFER *b, DWORD max_records)
{
    BYTE              *raw   = NULL;
    EYXA_BUFFER_BATCH *batch = NULL;
    DWORD              raw_len, read_len = 0;
    DWORD              p, rec, data_out, scan_end;
    LARGE_INTEGER      seek;

    if (b == NULL) return NULL;
    if (max_records == 0 || max_records > (DWORD)EYXA_BATCH_MAX_RECORDS)
        max_records = (DWORD)EYXA_BATCH_MAX_RECORDS;

    EnterCriticalSection(&b->lock);

    if (b->write_pos <= b->commit_pos) goto done; /* nothing pending */

    {
        UINT64 pending = b->write_pos - b->commit_pos;
        raw_len = (pending < (UINT64)EYXA_BATCH_MAX_READ)
                    ? (DWORD)pending
                    : (DWORD)EYXA_BATCH_MAX_READ;
    }

    raw = (BYTE *)malloc(raw_len);
    if (raw == NULL) goto done;

    seek.QuadPart = (LONGLONG)b->commit_pos;
    if (!SetFilePointerEx(b->log, seek, NULL, FILE_BEGIN) ||
        !ReadFile(b->log, raw, raw_len, &read_len, NULL) || read_len == 0)
        goto done;

    /* First pass: count valid records and measure output size. */
    p = rec = data_out = scan_end = 0;
    while (p + (DWORD)sizeof(EYXA_RECORD_HDR) <= read_len &&
           rec < max_records) {
        EYXA_RECORD_HDR hdr;
        memcpy(&hdr, raw + p, sizeof(hdr));
        if (hdr.magic != EYXA_BUFFER_MAGIC) break;                  /* corruption */
        if (p + (DWORD)sizeof(hdr) + hdr.payload_len > read_len) break; /* partial  */
        p        += (DWORD)sizeof(hdr) + hdr.payload_len;
        data_out += (DWORD)sizeof(DWORD) + hdr.payload_len;
        rec++;
    }
    scan_end = p;

    if (rec == 0) goto done;

    batch = (EYXA_BUFFER_BATCH *)calloc(
                1, offsetof(EYXA_BUFFER_BATCH, data) + data_out);
    if (batch == NULL) goto done;

    batch->end_offset   = b->commit_pos + (UINT64)scan_end;
    batch->record_count = rec;
    batch->data_bytes   = data_out;

    /* Second pass: copy records into batch, stripping the on-disk magic. */
    {
        DWORD  i, q = 0;
        BYTE  *out = batch->data;
        for (i = 0; i < rec; i++) {
            EYXA_RECORD_HDR hdr;
            DWORD len;
            memcpy(&hdr, raw + q, sizeof(hdr));
            q += (DWORD)sizeof(hdr);
            len = hdr.payload_len;
            memcpy(out, &len, sizeof(len));  out += sizeof(len);
            memcpy(out, raw + q, len);       out += len;
            q += len;
        }
    }

done:
    LeaveCriticalSection(&b->lock);
    free(raw);
    return batch;
}

void EyxaBufferBatchFree(EYXA_BUFFER_BATCH *batch)
{
    free(batch);
}

/*
 * Iterate records within a batch without allocating.
 * Set *offset = 0 on first call; advances automatically.
 * Returns NULL when all records have been visited.
 *
 * Usage:
 *   DWORD off = 0, len;
 *   const BYTE *rec;
 *   while ((rec = EyxaBufferBatchNext(batch, &off, &len)) != NULL) { ... }
 */
const BYTE *EyxaBufferBatchNext(const EYXA_BUFFER_BATCH *batch,
                                DWORD *offset_inout, DWORD *len_out)
{
    DWORD off, len;
    if (batch == NULL || offset_inout == NULL || len_out == NULL) return NULL;
    off = *offset_inout;
    if (off + (DWORD)sizeof(DWORD) > batch->data_bytes) return NULL;
    memcpy(&len, batch->data + off, sizeof(len));
    off += sizeof(len);
    if (off + len > batch->data_bytes) return NULL;
    *offset_inout = off + len;
    *len_out      = len;
    return batch->data + off;
}

/*
 * Advance the committed cursor to through_offset.
 * When the cursor reaches write_pos (all data sent), both files are reset
 * to keep their sizes bounded.
 */
BOOL EyxaBufferCommit(EYXA_BUFFER *b, UINT64 through_offset)
{
    BOOL ok;
    if (b == NULL) return FALSE;
    EnterCriticalSection(&b->lock);
    if (through_offset > b->write_pos) through_offset = b->write_pos;
    ok = EyxaWriteCursorAtomically(b->cursor_path, through_offset);
    if (ok) {
        b->commit_pos = through_offset;
        if (b->commit_pos == b->write_pos && b->write_pos > 0)
            EyxaTrimLog(b);
    }
    LeaveCriticalSection(&b->lock);
    return ok;
}

/* Records lost to overflow since last call (read-only; counter not reset). */
LONG EyxaBufferOverflowCount(EYXA_BUFFER *b)
{
    if (b == NULL) return 0;
    return InterlockedCompareExchange(&b->overflow_count, 0, 0);
}

#endif /* EYXA_BUFFER_C */
