@ECHO OFF

NET SESSIONS > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 (
	ECHO Error: This script requires administrative privileges.
	EXIT /B 1
)

SET SYSDIR="%WINDIR%\System32"

SET EMU_ROOT=root
SET EMU_FILESYS=%EMU_ROOT%\filesys
SET EMU_WINDIR=%EMU_FILESYS%\c\windows
SET EMU_SYSDIR=%EMU_WINDIR%\system32
SET EMU_REGDIR=%EMU_ROOT%\registry

MKDIR %EMU_SYSDIR%
MKDIR %EMU_REGDIR%

REG SAVE HKLM\SYSTEM %EMU_REGDIR%\SYSTEM /Y
REG SAVE HKLM\SECURITY %EMU_REGDIR%\SECURITY /Y
REG SAVE HKLM\SOFTWARE %EMU_REGDIR%\SOFTWARE /Y
REG SAVE HKLM\HARDWARE %EMU_REGDIR%\HARDWARE /Y
REG SAVE HKLM\SAM %EMU_REGDIR%\SAM /Y
COPY /B /Y C:\Users\Default\NTUSER.DAT "%EMU_REGDIR%\NTUSER.DAT"

CALL :collect advapi32.dll
CALL :collect bcrypt.dll
CALL :collect cfgmgr32.dll
CALL :collect ci.dll
CALL :collect combase.dll
CALL :collect comctl32.dll
CALL :collect comdlg32.dll
CALL :collect crypt32.dll
CALL :collect cryptbase.dll
CALL :collect gdi32.dll
CALL :collect hal.dll
CALL :collect iphlpapi.dll
CALL :collect kdcom.dll
CALL :collect kernel32.dll
CALL :collect kernelbase.dll
CALL :collect mpr.dll
CALL :collect mscoree.dll
CALL :collect msvcp_win.dll
CALL :collect msvcp60.dll
CALL :collect msvcr120_clr0400.dll
CALL :collect msvcrt.dll
CALL :collect netapi32.dll
CALL :collect ntdll.dll
CALL :collect ole32.dll
CALL :collect oleaut32.dll
CALL :collect psapi.dll
CALL :collect rpcrt4.dll
CALL :collect sechost.dll
CALL :collect setupapi.dll
CALL :collect shell32.dll
CALL :collect shlwapi.dll
CALL :collect sspicli.dll
CALL :collect ucrtbase.dll
CALL :collect ucrtbased.dll
CALL :collect urlmon.dll
CALL :collect user32.dll
CALL :collect userenv.dll
CALL :collect uxtheme.dll
CALL :collect vcruntime140.dll
CALL :collect vcruntime140d.dll
CALL :collect vcruntime140_1.dll
CALL :collect vcruntime140_1d.dll
CALL :collect version.dll
CALL :collect win32u.dll
CALL :collect winhttp.dll
CALL :collect wininet.dll
CALL :collect winmm.dll
CALL :collect ws2_32.dll
CALL :collect wsock32.dll
CALL :collect msvcp140.dll
CALL :collect msvcp140d.dll
CALL :collect d3d11.dll
CALL :collect d3d9.dll
CALL :collect d3d12.dll
CALL :collect d3dcompiler_47.dll
CALL :collect dxgi.dll
CALL :collect dsound.dll
CALL :collect dwmapi.dll
CALL :collect hid.dll
CALL :collect imm32.dll
CALL :collect uiautomationcore.dll
CALL :collect opengl32.dll
CALL :collect normaliz.dll
CALL :collect wintrust.dll
CALL :collect wldap32.dll
CALL :collect wtsapi32.dll
CALL :collect x3daudio1_7.dll
CALL :collect xapofx1_5.dll
CALL :collect xinput1_3.dll
CALL :collect xinput9_1_0.dll
CALL :collect cryptsp.dll
CALL :collect resampledmo.dll
CALL :collect powrprof.dll
CALL :collect winmmbase.dll
CALL :collect gdi32full.dll
CALL :collect glu32.dll
CALL :collect msdmo.dll
CALL :collect dxcore.dll
CALL :collect mfplat.dll
CALL :collect wer.dll
CALL :collect dbghelp.dll
CALL :collect mscms.dll
CALL :collect ktmw32.dll
CALL :collect shcore.dll
CALL :collect diagnosticdatasettings.dll
CALL :collect mswsock.dll
CALL :collect umpdc.dll
CALL :collect pdh.dll
CALL :collect dxva2.dll
CALL :collect propsys.dll
CALL :collect wintypes.dll
CALL :collect slwga.dll
CALL :collect sppc.dll
CALL :collect kernel.appcore.dll
CALL :collect windows.storage.dll
CALL :collect winnlsres.dll
CALL :collect nlsbres.dll
CALL :collect netutils.dll
CALL :collect dinput8.dll
CALL :collect d3d10.dll
CALL :collect d3d10core.dll
CALL :collect cabinet.dll
CALL :collect msacm32.dll
CALL :collect coloradapterclient.dll
CALL :collect netmsg.dll
CALL :collect rstrtmgr.dll
CALL :collect ncrypt.dll
CALL :collect ntasn1.dll
CALL :collect srvcli.dll

CALL :collect locale.nls
CALL :collect c_1252.nls
CALL :collect c_850.nls
CALL :collect c_437.nls

EXIT /B 0

:normpath
SET %1=%~dpfn2
EXIT /B

:collect_file
CALL :normpath SRC, %~1\%~2
CALL :normpath DST, %~3\%~2

IF EXIST %SRC% (
	ECHO %SRC% -^> %DST%
	COPY /B /Y "%SRC%" "%DST%" >NUL
)
EXIT /B

:collect
CALL :collect_file %SYSDIR%, %~1, %EMU_SYSDIR%
EXIT /B
