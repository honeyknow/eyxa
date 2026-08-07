# Eyxa agent Makefile
# Compiler: MSVC (cl.exe) via a VS Developer Command Prompt.
# Usage from a VS Developer Command Prompt (x64):
#   cd c:\product\eyxa\agent
#   nmake                     -- build all
#   nmake test_buffer.exe     -- build one test
#   nmake clean               -- clean all outputs

CC     = cl.exe
CFLAGS = /nologo /W4 /WX /O2 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0602 \
         /I"$(VSINSTALLDIR)VC\Tools\MSVC\$(VCToolsVersion)\include" \
         /I"$(WindowsSdkDir)Include\$(WindowsSDKVersion)um" \
         /I"$(WindowsSdkDir)Include\$(WindowsSDKVersion)shared" \
         /I"$(WindowsSdkDir)Include\$(WindowsSDKVersion)ucrt"

LDFLAGS_COMMON = advapi32.lib ole32.lib shell32.lib wevtapi.lib \
                 winhttp.lib kernel32.lib ws2_32.lib \
                 /link /SUBSYSTEM:CONSOLE

# Production agent sources (all compiled into one eyxa.exe)
AGENT_SRCS = src\sysmon_reader.c \
             src\amsi_reader.c   \
             src\buffer.c        \
             src\enrollment.c    \
             src\sender.c        \
             src\ws_client.c

# ── targets ────────────────────────────────────────────────────────────
all: eyxa.exe test_buffer.exe test_enrollment.exe test_sysmon_reader.exe test_amsi_reader.exe

eyxa.exe: src\main.c
	$(CC) $(CFLAGS) /Fe:..\..\garbage\eyxa.exe \
		src\main.c \
		$(LDFLAGS_COMMON)

# buffer.c test (standalone, no backend required)
test_buffer.exe: ..\..\garbage\test_buffer.c src\buffer.c
	$(CC) $(CFLAGS) /Fe:..\..\garbage\test_buffer.exe \
		..\..\garbage\test_buffer.c \
		$(LDFLAGS_COMMON)

# enrollment.c test (machine-identity and token persistence only)
test_enrollment.exe: ..\..\garbage\test_enrollment.c src\enrollment.c
	$(CC) $(CFLAGS) /Fe:..\..\garbage\test_enrollment.exe \
		..\..\garbage\test_enrollment.c \
		$(LDFLAGS_COMMON)

# sysmon_reader.c test (requires Sysmon installed + run as Admin)
test_sysmon_reader.exe: ..\..\garbage\test_sysmon_reader.c src\sysmon_reader.c
	$(CC) $(CFLAGS) /Fe:..\..\garbage\test_sysmon_reader.exe \
		..\..\garbage\test_sysmon_reader.c \
		$(LDFLAGS_COMMON)

# amsi_reader.c test (requires run as Admin)
test_amsi_reader.exe: ..\..\garbage\test_amsi_reader.c src\amsi_reader.c
	$(CC) $(CFLAGS) /Fe:..\..\garbage\test_amsi_reader.exe \
		..\..\garbage\test_amsi_reader.c \
		advapi32.lib ole32.lib shell32.lib wevtapi.lib \
		/link /SUBSYSTEM:CONSOLE

clean:
	del /Q ..\..\garbage\test_buffer.exe 2>nul
	del /Q ..\..\garbage\test_enrollment.exe 2>nul
	del /Q ..\..\garbage\test_sysmon_reader.exe 2>nul
	del /Q ..\..\garbage\test_amsi_reader.exe 2>nul
	del /Q *.obj 2>nul
