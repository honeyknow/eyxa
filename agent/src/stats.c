#ifndef EYXA_STATS_C
#define EYXA_STATS_C

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <winioctl.h>
#include <pdh.h>
#include <pdhmsg.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "iphlpapi.lib")

/* ── OS build (RtlGetVersion from ntdll) ───────────────────────────── */
typedef LONG (WINAPI *RtlGetVersionPtr)(POSVERSIONINFOW);

/* ── Hardware Inventory ────────────────────────────────────────────── */

static void EyxaGetCpuName(WCHAR *out_buf, DWORD chars) {
    HKEY key;
    DWORD type, size = chars * sizeof(WCHAR);
    out_buf[0] = L'\0';
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &key) == ERROR_SUCCESS) {
        RegQueryValueExW(key, L"ProcessorNameString", NULL, &type, (LPBYTE)out_buf, &size);
        RegCloseKey(key);
    }
}

static void EyxaGetOsBuild(WCHAR *out_buf, DWORD chars) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    OSVERSIONINFOW osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    out_buf[0] = L'\0';
    
    if (ntdll) {
        RtlGetVersionPtr func = (RtlGetVersionPtr)GetProcAddress(ntdll, "RtlGetVersion");
        if (func && func(&osvi) == 0) {
            swprintf(out_buf, chars, L"Windows %lu.%lu Build %lu",
                     osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
            return;
        }
    }
    swprintf(out_buf, chars, L"Unknown OS");
}

/* 
 * Query physical drives for capacity and serial. 
 * Since this is JSON, we build an array string directly. 
 */
static void EyxaGetStorageJson(char *json_out, size_t max_len) {
    char buf[1024] = "[]";
    HANDLE h;
    WCHAR path[64];
    STORAGE_PROPERTY_QUERY query;
    char out_buf[1024];
    DWORD bytes;
    int pos = 0;
    int disk = 0;
    
    pos += _snprintf_s(buf + pos, sizeof(buf) - pos, _TRUNCATE, "[");
    
    for (disk = 0; disk < 8; disk++) {
        swprintf(path, 64, L"\\\\.\\PhysicalDrive%d", disk);
        h = CreateFileW(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            query.PropertyId = StorageDeviceProperty;
            query.QueryType = PropertyStandardQuery;
            if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), out_buf, sizeof(out_buf), &bytes, NULL)) {
                STORAGE_DEVICE_DESCRIPTOR *desc = (STORAGE_DEVICE_DESCRIPTOR *)out_buf;
                char *serial = "";
                if (desc->SerialNumberOffset > 0) {
                    serial = out_buf + desc->SerialNumberOffset;
                }
                
                /* strip whitespace from serial */
                char clean_serial[256] = {0};
                int j = 0;
                for (int i = 0; serial[i] && j < 255; i++) {
                    if (serial[i] > 32) clean_serial[j++] = serial[i];
                }
                
                /* Guard: _snprintf_s returns -1 on truncation; clamp to prevent pos wrap. */
                if (disk > 0) {
                    int _n = _snprintf_s(buf + pos, sizeof(buf) - pos, _TRUNCATE, ",");
                    if (_n > 0) pos += _n;
                }
                { int _n = _snprintf_s(buf + pos, sizeof(buf) - pos, _TRUNCATE,
                      "{\"drive\":%d,\"serial\":\"%s\"}", disk, clean_serial);
                  if (_n > 0) pos += _n; }
            }
            CloseHandle(h);
        }
    }
    pos += _snprintf_s(buf + pos, sizeof(buf) - pos, _TRUNCATE, "]");
    strncpy_s(json_out, max_len, buf, _TRUNCATE);
}

static void EyxaGetNetworkJson(char *json_out, size_t max_len) {
    ULONG buflen = 15000;
    IP_ADAPTER_ADDRESSES *addrs = (IP_ADAPTER_ADDRESSES *)malloc(buflen);
    char buf[4096];
    int pos = 0;
    int count = 0;
    
    pos += _snprintf_s(buf + pos, sizeof(buf) - pos, _TRUNCATE, "[");
    
    if (addrs && GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, addrs, &buflen) == NO_ERROR) {
        IP_ADAPTER_ADDRESSES *p = addrs;
        while (p) {
            if (p->PhysicalAddressLength == 6) {
                /* Convert adapter name to UTF-8; %ws is non-standard and embeds raw
                 * wide bytes into a char buffer on non-English systems (H-4 fix). */
                char name_u8[256] = {0};
                WideCharToMultiByte(CP_UTF8, 0, p->FriendlyName, -1,
                                    name_u8, (int)sizeof(name_u8)-1, NULL, NULL);
                /* Escape any quotes or backslashes in the adapter name. */
                for (char *_q = name_u8; *_q; _q++) {
                    if (*_q == '"') *_q = '\'';
                    else if (*_q == '\\') *_q = '/';
                }
                if (count > 0) { int _n = _snprintf_s(buf + pos, sizeof(buf) - pos, _TRUNCATE, ","); if (_n > 0) pos += _n; }
                { int _n = _snprintf_s(buf + pos, sizeof(buf) - pos, _TRUNCATE,
                      "{\"name\":\"%s\",\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\"}",
                      name_u8,
                      p->PhysicalAddress[0], p->PhysicalAddress[1], p->PhysicalAddress[2],
                      p->PhysicalAddress[3], p->PhysicalAddress[4], p->PhysicalAddress[5]);
                  if (_n > 0) pos += _n; }
                count++;
            }
            p = p->Next;
        }
    }
    if (addrs) free(addrs);
    pos += _snprintf_s(buf + pos, sizeof(buf) - pos, _TRUNCATE, "]");
    strncpy_s(json_out, max_len, buf, _TRUNCATE);
}

/* Get inventory JSON (sent via WS) */
BOOL EyxaHardwareInventory(char *json_out, size_t max_len) {
    WCHAR cpu[256];
    WCHAR os[128];
    char storage[1024];
    char network[4096];
    MEMORYSTATUSEX mem;
    
    EyxaGetCpuName(cpu, 256);
    EyxaGetOsBuild(os, 128);
    EyxaGetStorageJson(storage, sizeof(storage));
    EyxaGetNetworkJson(network, sizeof(network));
    
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    
    int len = _snprintf_s(json_out, max_len, _TRUNCATE,
        "{\"type\":\"inventory\",\"os_build\":\"%ws\",\"cpu\":\"%ws\",\"ram_mb\":%llu,"
        "\"storage\":%s,\"network\":%s}",
        os, cpu, (unsigned long long)(mem.ullTotalPhys / (1024ULL * 1024ULL)),
        storage, network);
        
    return (len > 0 && (size_t)len < max_len);
}

/* ── Live Usage (PDH) ──────────────────────────────────────────────── */

typedef struct {
    PDH_HQUERY hQuery;
    PDH_HCOUNTER hCpu;
    PDH_HCOUNTER hDisk;
    PDH_HCOUNTER hNetRecv;
    PDH_HCOUNTER hNetSent;
    BOOL active;
} EYXA_PDH_STATE;

static EYXA_PDH_STATE g_pdh = {0};

/* Init PDH counters (called once by ws_client thread) */
BOOL EyxaLiveStatsInit(void) {
    PDH_STATUS s;
    if (g_pdh.active) return TRUE;
    
    s = PdhOpenQueryW(NULL, 0, &g_pdh.hQuery);
    if (s != ERROR_SUCCESS) return FALSE;
    
    /* English counter names are used for reliability, but localized OS might need translated paths.
     * We use standard \Object\Counter format. For robustness in global environments, English is standard. */
    PdhAddEnglishCounterW(g_pdh.hQuery, L"\\Processor Information(_Total)\\% Processor Time", 0, &g_pdh.hCpu);
    PdhAddEnglishCounterW(g_pdh.hQuery, L"\\PhysicalDisk(_Total)\\% Disk Time", 0, &g_pdh.hDisk);
    PdhAddEnglishCounterW(g_pdh.hQuery, L"\\Network Interface(*)\\Bytes Received/sec", 0, &g_pdh.hNetRecv);
    PdhAddEnglishCounterW(g_pdh.hQuery, L"\\Network Interface(*)\\Bytes Sent/sec", 0, &g_pdh.hNetSent);
    
    PdhCollectQueryData(g_pdh.hQuery); /* First collection (baseline) */
    g_pdh.active = TRUE;
    return TRUE;
}

/* Read live stats and output JSON */
BOOL EyxaLiveStatsPoll(char *json_out, size_t max_len) {
    PDH_FMT_COUNTERVALUE val;
    DWORD cpu = 0, disk = 0;
    ULONGLONG net_bytes = 0;
    MEMORYSTATUSEX mem;
    ULONGLONG ts;
    FILETIME sys_time;
    
    if (!g_pdh.active) return FALSE;
    
    PdhCollectQueryData(g_pdh.hQuery);
    
    if (PdhGetFormattedCounterValue(g_pdh.hCpu, PDH_FMT_LONG, NULL, &val) == ERROR_SUCCESS) {
        cpu = val.longValue;
    }
    if (PdhGetFormattedCounterValue(g_pdh.hDisk, PDH_FMT_LONG, NULL, &val) == ERROR_SUCCESS) {
        disk = val.longValue;
        if (disk > 100) disk = 100; /* Disk time can exceed 100% on RAIDs/concurrent IO, cap for UI */
    }
    
    /* Network counters have multiple instances (interfaces), we sum them up */
    {
        DWORD buf_size = 0, count = 0;
        PdhGetRawCounterArrayW(g_pdh.hNetRecv, &buf_size, &count, NULL);
        if (buf_size > 0) {
            PDH_RAW_COUNTER_ITEM_W *items = (PDH_RAW_COUNTER_ITEM_W *)malloc(buf_size);
            if (items && PdhGetRawCounterArrayW(g_pdh.hNetRecv, &buf_size, &count, items) == ERROR_SUCCESS) {
                for (DWORD i = 0; i < count; i++) {
                    if (wcsstr(items[i].szName, L"Loopback") == NULL) { /* Ignore loopback */
                        /* For raw counters, we technically need 2 samples to compute rate.
                         * Let's use FormattedCounterArray for easier rate parsing. */
                    }
                }
            }
            if (items) free(items);
        }
    }
    
    /* Better approach for Network: just use Formatted array */
    {
        DWORD buf_size = 0, count = 0;
        PdhGetFormattedCounterArrayW(g_pdh.hNetRecv, PDH_FMT_LARGE, &buf_size, &count, NULL);
        if (buf_size > 0) {
            PDH_FMT_COUNTERVALUE_ITEM_W *items = (PDH_FMT_COUNTERVALUE_ITEM_W *)malloc(buf_size);
            if (items && PdhGetFormattedCounterArrayW(g_pdh.hNetRecv, PDH_FMT_LARGE, &buf_size, &count, items) == ERROR_SUCCESS) {
                for (DWORD i = 0; i < count; i++) {
                    if (wcsstr(items[i].szName, L"Loopback") == NULL && items[i].FmtValue.CStatus == PDH_CSTATUS_VALID_DATA) {
                        net_bytes += items[i].FmtValue.largeValue;
                    }
                }
            }
            if (items) free(items);
        }
        
        buf_size = 0; count = 0;
        PdhGetFormattedCounterArrayW(g_pdh.hNetSent, PDH_FMT_LARGE, &buf_size, &count, NULL);
        if (buf_size > 0) {
            PDH_FMT_COUNTERVALUE_ITEM_W *items = (PDH_FMT_COUNTERVALUE_ITEM_W *)malloc(buf_size);
            if (items && PdhGetFormattedCounterArrayW(g_pdh.hNetSent, PDH_FMT_LARGE, &buf_size, &count, items) == ERROR_SUCCESS) {
                for (DWORD i = 0; i < count; i++) {
                    if (wcsstr(items[i].szName, L"Loopback") == NULL && items[i].FmtValue.CStatus == PDH_CSTATUS_VALID_DATA) {
                        net_bytes += items[i].FmtValue.largeValue;
                    }
                }
            }
            if (items) free(items);
        }
    }
    
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    
    GetSystemTimeAsFileTime(&sys_time);
    /* C-1 fix: parenthesise the full 64-bit combine BEFORE subtracting the epoch offset.
     * Without parens, '-' binds tighter than '|', causing dwLowDateTime to underflow. */
    ts = ((((UINT64)sys_time.dwHighDateTime << 32) | (UINT64)sys_time.dwLowDateTime)
          - 116444736000000000ULL) / 10000000ULL;
    
    int len = _snprintf_s(json_out, max_len, _TRUNCATE,
        "{\"type\":\"stats\",\"ts\":%llu,\"cpu_pct\":%lu,"
        "\"mem_total_mb\":%llu,\"mem_free_mb\":%llu,\"disk_pct\":%lu,\"net_bps\":%llu}",
        (unsigned long long)ts, (unsigned long)cpu,
        (unsigned long long)(mem.ullTotalPhys / (1024ULL * 1024ULL)),
        (unsigned long long)(mem.ullAvailPhys / (1024ULL * 1024ULL)),
        (unsigned long)disk, (unsigned long long)(net_bytes * 8)); /* bytes to bits */
        
    return (len > 0 && (size_t)len < max_len);
}

#endif /* EYXA_STATS_C */
