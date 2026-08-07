/*
 * shared_status.h -- Named shared memory block written by eyxa.exe (service)
 * and read by terminator.exe (tray watchdog UI process).
 *
 * Mapping name: "Local\EyxaStatusBlock"
 * Size: sizeof(EYXA_SHARED_STATUS)
 * Writer: eyxa.exe (SYSTEM, Session 0) - updated every 30s by heartbeat thread
 * Reader: terminator.exe (user session) - polled every 10s by tray watchdog
 *
 * Source: https://learn.microsoft.com/en-us/windows/win32/memory/creating-named-shared-memory
 *
 * Thread safety: writer uses InterlockedExchange on sequence number (seqlock).
 * Reader checks seq_begin == seq_end to detect torn reads and retries once.
 */

#pragma once
#ifndef EYXA_SHARED_STATUS_H
#define EYXA_SHARED_STATUS_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define EYXA_STATUS_MAP_NAME  L"Global\\EyxaStatusBlock"
#define EYXA_STATUS_MAP_SIZE  512

/* Health enumeration - written by eyxa.exe, read by terminator.exe */
typedef enum {
    EYXA_HEALTH_STARTING   = 0,  /* service just started */
    EYXA_HEALTH_OK         = 1,  /* all modules alive */
    EYXA_HEALTH_DEGRADED   = 2,  /* one or more non-fatal module failures */
    EYXA_HEALTH_ERROR      = 3,  /* fatal failure - service alive but broken */
} EYXA_HEALTH;

/* Flags for which modules are alive */
#define EYXA_MOD_SYSMON   (1 << 0)
#define EYXA_MOD_AMSI     (1 << 1)
#define EYXA_MOD_CHANNEL  (1 << 2)
#define EYXA_MOD_SENDER   (1 << 3)
#define EYXA_MOD_WS       (1 << 4)
#define EYXA_MOD_DNS      (1 << 5)
#define EYXA_MOD_TAMPER   (1 << 6)

#pragma pack(push, 1)
typedef struct {
    volatile LONG seq_begin;       /* seqlock: odd = write in progress */
    EYXA_HEALTH   health;          /* overall agent health */
    DWORD         modules_alive;   /* bitmask of EYXA_MOD_* */
    LONGLONG      events_total;    /* total events written to buffer since start */
    LONGLONG      events_sent;     /* total events flushed to backend */
    LONGLONG      last_event_tick; /* GetTickCount64() of last event received */
    LONGLONG      uptime_seconds;  /* seconds since RunAgent() started */
    WCHAR         backend_host[64];/* backend hostname (for status popup) */
    WCHAR         last_alert[128]; /* last alert title (for tray tooltip) */
    volatile LONG seq_end;         /* seqlock: must equal seq_begin after write */
} EYXA_SHARED_STATUS;
#pragma pack(pop)

/* Writer helpers (called from eyxa.exe) */
static __inline void EyxaStatusBeginWrite(EYXA_SHARED_STATUS *s) {
    InterlockedIncrement(&s->seq_begin); /* make odd */
    MemoryBarrier();
}
static __inline void EyxaStatusEndWrite(EYXA_SHARED_STATUS *s) {
    MemoryBarrier();
    InterlockedIncrement(&s->seq_end); /* match seq_begin, make even */
}

#endif /* EYXA_SHARED_STATUS_H */
