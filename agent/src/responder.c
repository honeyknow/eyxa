/*
 * Eyxa agent response action executor -- Phase 6.
 *
 * Receives JSON response action commands from ws_client.c, parses command type
 * and parameters, executes Win32 APIs, and returns JSON result payload over
 * WebSocket.
 *
 * Supported Actions:
 *   1. "kill_process"
 *      Payload: {"pid": <DWORD>}
 *      Win32 APIs:
 *        OpenProcess(PROCESS_TERMINATE, FALSE, pid)
 *        // Source: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
 *        TerminateProcess(hProcess, 1)
 *        // Source: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess
 *        CloseHandle(hProcess)
 *        // Source: https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ws_client.c"

/* Simple Base64 encoder */
static const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static char *EyxaBase64Encode(const BYTE *in, DWORD in_len, DWORD *out_len) {
    DWORD out_sz = 4 * ((in_len + 2) / 3) + 1;
    char *out = (char *)malloc(out_sz);
    if (!out) return NULL;
    DWORD i, j = 0;
    for (i = 0; i < in_len;) {
        DWORD octet_a = i < in_len ? in[i++] : 0;
        DWORD octet_b = i < in_len ? in[i++] : 0;
        DWORD octet_c = i < in_len ? in[i++] : 0;
        DWORD triple = (octet_a << 16) + (octet_b << 8) + octet_c;
        out[j++] = b64chars[(triple >> 18) & 0x3F];
        out[j++] = b64chars[(triple >> 12) & 0x3F];
        out[j++] = i > in_len + 1 ? '=' : b64chars[(triple >> 6) & 0x3F];
        out[j++] = i > in_len ? '=' : b64chars[triple & 0x3F];
    }
    out[j] = '\0';
    if (out_len) *out_len = j;
    return out;
}

/* Simple helper to extract integer value for a key from JSON string */
static BOOL EyxaJsonGetInt(const char *json, const char *key, DWORD *val_out)
{
    char search_key[128];
    const char *p;
    if (!json || !key || !val_out) return FALSE;

    _snprintf_s(search_key, sizeof(search_key), _TRUNCATE, "\"%s\":", key);
    p = strstr(json, search_key);
    if (!p) {
        _snprintf_s(search_key, sizeof(search_key), _TRUNCATE, "\"%s\" :", key);
        p = strstr(json, search_key);
    }
    if (!p) return FALSE;

    p = strchr(p, ':');
    if (!p) return FALSE;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;

    *val_out = (DWORD)strtoul(p, NULL, 10);
    return TRUE;
}

/* Simple helper to extract string value for a key from JSON */
static BOOL EyxaJsonGetString(const char *json, const char *key, char *buf_out, DWORD buf_size)
{
    char search_key[128];
    const char *p;
    const char *end;
    DWORD len;

    if (!json || !key || !buf_out || buf_size == 0) return FALSE;

    _snprintf_s(search_key, sizeof(search_key), _TRUNCATE, "\"%s\":", key);
    p = strstr(json, search_key);
    if (!p) {
        _snprintf_s(search_key, sizeof(search_key), _TRUNCATE, "\"%s\" :", key);
        p = strstr(json, search_key);
    }
    if (!p) return FALSE;

    p = strchr(p, ':');
    if (!p) return FALSE;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;

    if (*p != '"') return FALSE;
    p++; /* skip opening quote */

    /* M-3 fix: walk until an UNESCAPED closing quote is found.
     * The old strchr(p, '"') would stop at \" inside the string value. */
    end = p;
    while (*end && !(*end == '"' && (end == p || *(end-1) != '\\'))) end++;
    if (!*end) return FALSE;

    len = (DWORD)(end - p);
    if (len >= buf_size) len = buf_size - 1;

    memcpy(buf_out, p, len);
    buf_out[len] = '\0';
    return TRUE;
}

/*
 * Callback passed to EyxaWsClientStart.
 * Called on receive thread for incoming WebSocket messages from backend.
 */
void EyxaCommandCallback(const BYTE *data, DWORD len, void *context)
{
    EYXA_WS_CLIENT *client = (EYXA_WS_CLIENT *)context;
    char *json = NULL;
    DWORD command_id = 0;
    char action[64] = {0};
    char response_json[512] = {0};
    DWORD resp_len = 0;

    if (!data || len == 0 || !client) return;

    json = (char *)malloc(len + 1);
    if (!json) return;
    memcpy(json, data, len);
    json[len] = '\0';

    /* Parse command_id and action */
    if (!EyxaJsonGetInt(json, "command_id", &command_id)) {
        free(json);
        return;
    }
    EyxaJsonGetString(json, "action", action, sizeof(action));

    if (strcmp(action, "kill_process") == 0) {
        DWORD pid = 0;
        BOOL ok = FALSE;
        DWORD err = 0;

        if (EyxaJsonGetInt(json, "pid", &pid) && pid > 0) {
            // Source: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
            HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
            if (hProc) {
                // Source: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess
                if (TerminateProcess(hProc, 1)) {
                    ok = TRUE;
                } else {
                    err = GetLastError();
                }
                // Source: https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
                CloseHandle(hProc);
            } else {
                err = GetLastError();
            }
        }

        resp_len = (DWORD)_snprintf_s(
            response_json, sizeof(response_json), _TRUNCATE,
            "{\"type\":\"command_result\",\"command_id\":%lu,\"status\":\"%s\",\"result\":{\"success\":%s,\"win32_error\":%lu}}",
            (unsigned long)command_id,
            ok ? "completed" : "failed",
            ok ? "true" : "false",
            (unsigned long)err
        );
    } else if (strcmp(action, "run_command") == 0) {
        char cmd[1024] = {0};
        BOOL ok = FALSE;
        DWORD err = 0;
        char *b64 = NULL;
        
        if (EyxaJsonGetString(json, "command", cmd, sizeof(cmd))) {
            HANDLE hRead, hWrite;
            SECURITY_ATTRIBUTES sa;
            sa.nLength = sizeof(sa);
            sa.bInheritHandle = TRUE;
            sa.lpSecurityDescriptor = NULL;
            
            if (CreatePipe(&hRead, &hWrite, &sa, 0)) {
                SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);
                
                STARTUPINFOW si;
                ZeroMemory(&si, sizeof(si));
                si.cb = sizeof(si);
                si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
                si.hStdOutput = hWrite;
                si.hStdError = hWrite;
                si.wShowWindow = SW_HIDE;
                
                PROCESS_INFORMATION pi;
                ZeroMemory(&pi, sizeof(pi));
                
                WCHAR wCmd[1152];
                char wrapped_cmd[1152]; /* P-2 fix: 1024 cmd + 128 prefix margin */
                _snprintf_s(wrapped_cmd, sizeof(wrapped_cmd), _TRUNCATE, "cmd.exe /d /c \"%s\"", cmd);
                MultiByteToWideChar(CP_UTF8, 0, wrapped_cmd, -1, wCmd, ARRAYSIZE(wCmd));
                
                if (CreateProcessW(NULL, wCmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                    CloseHandle(hWrite); /* Close parent write-end so child can own it */
                    CloseHandle(pi.hThread);

                    /* R-2 fix: Wait for child exit BEFORE draining the pipe.
                     * Previous order (ReadFile then Wait) caused an indefinite
                     * block: ReadFile waits for EOF, which only arrives when the
                     * child closes its stdout — but a non-terminating process
                     * never does, so Wait was unreachable.
                     *
                     * Correct flow:
                     *   1. Wait up to 30s for process exit.
                     *   2. Kill if timeout (child's write handle auto-closed).
                     *   3. ReadFile drains the pipe (finite; process is dead).
                     *
                     * Edge case: child writing > pipe buffer (~64KB) blocks
                     * on stdout before exiting. WaitForSingleObject times out,
                     * we kill it, and we get whatever was buffered. Acceptable.
                     * Source: https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject */
                    if (WaitForSingleObject(pi.hProcess, 30000) == WAIT_TIMEOUT) {
                        TerminateProcess(pi.hProcess, 1);
                        WaitForSingleObject(pi.hProcess, 2000); /* ensure write-end is closed */
                    }
                    CloseHandle(pi.hProcess);

                    /* Drain pipe (process dead -> EOF arrives quickly) */
                    DWORD buf_cap = 65536;
                    DWORD buf_len = 0;
                    BYTE *buf = (BYTE *)malloc(buf_cap);
                    DWORD bytes_read;

                    if (buf) {
                        while (ReadFile(hRead, buf + buf_len, buf_cap - buf_len, &bytes_read, NULL) && bytes_read > 0) {
                            buf_len += bytes_read;
                            if (buf_len == buf_cap) {
                                buf_cap *= 2;
                                BYTE *new_buf = (BYTE *)realloc(buf, buf_cap);
                                if (!new_buf) { free(buf); buf = NULL; break; }
                                buf = new_buf;
                            }
                        }
                        if (buf) {
                            b64 = EyxaBase64Encode(buf, buf_len, NULL);
                            ok = (b64 != NULL);
                            free(buf);
                        }
                    }
                } else {
                    err = GetLastError();
                    CloseHandle(hWrite);
                }
                CloseHandle(hRead);
            } else {
                err = GetLastError();
            }
        }
        
        if (ok && b64) {
            DWORD resp_cap = (DWORD)strlen(b64) + 256;
            char *resp_dyn = (char *)malloc(resp_cap);
            if (resp_dyn) {
                DWORD rlen = (DWORD)_snprintf_s(
                    resp_dyn, resp_cap, _TRUNCATE,
                    "{\"type\":\"command_result\",\"command_id\":%lu,\"status\":\"completed\",\"result\":{\"success\":true,\"output_b64\":\"%s\"}}",
                    (unsigned long)command_id, b64
                );
                if (rlen > 0 && rlen < resp_cap) {
                    EyxaWsSend(client, resp_dyn, rlen);
                }
                free(resp_dyn);
            }
            resp_len = 0; /* Skip the standard send */
            free(b64);
        } else {
            resp_len = (DWORD)_snprintf_s(
                response_json, sizeof(response_json), _TRUNCATE,
                "{\"type\":\"command_result\",\"command_id\":%lu,\"status\":\"failed\",\"result\":{\"success\":false,\"win32_error\":%lu}}",
                (unsigned long)command_id, (unsigned long)err
            );
        }
    } else {
        /* Unknown action */
        resp_len = (DWORD)_snprintf_s(
            response_json, sizeof(response_json), _TRUNCATE,
            "{\"type\":\"command_result\",\"command_id\":%lu,\"status\":\"failed\",\"result\":{\"error\":\"unknown action\"}}",
            (unsigned long)command_id
        );
    }

    if (resp_len > 0 && resp_len < sizeof(response_json)) {
        EyxaWsSend(client, response_json, resp_len);
    }

    free(json);
}
