; ARGUS Windows installer — NSIS script
;
; Builds argus-setup.exe. Double-click presents a standard Windows
; wizard (Welcome / License / Install Location / Progress / Finish)
; and installs argus.exe to %LOCALAPPDATA%\Programs\argus plus adds
; that directory to the user PATH. No admin required.
;
; Build (macOS / Linux):
;   cd scripts && makensis argus-installer.nsi
;
; Artifact: scripts/dist/argus-setup.exe

!define APP_NAME     "ARGUS"
!define APP_VERSION  "1.0.0"
!define APP_PUBLISHER "vatsayanvivek"
!define APP_URL      "https://github.com/vatsayanvivek/argus"
!define APP_EXE      "argus.exe"

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "WinMessages.nsh"
!include "StrFunc.nsh"

; Activate the StrFunc macros we need (NSIS requires opt-in).
${StrStr}

Name "${APP_NAME} ${APP_VERSION}"
OutFile "dist\argus-setup.exe"
Unicode true

InstallDir "$LOCALAPPDATA\Programs\argus"
InstallDirRegKey HKCU "Software\${APP_NAME}" "InstallDir"

; User-level privileges — no UAC prompt.
RequestExecutionLevel user

SetCompressor /SOLID lzma

!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES

!define MUI_FINISHPAGE_TEXT "ARGUS has been installed to $INSTDIR and added to your user PATH.$\r$\n$\r$\nOpen a new PowerShell window and run 'argus --version' to verify.$\r$\n$\r$\nClick Finish to close this installer."
!define MUI_FINISHPAGE_SHOWREADME ""
!define MUI_FINISHPAGE_SHOWREADME_NOTCHECKED
!define MUI_FINISHPAGE_SHOWREADME_TEXT "View README on GitHub"
!define MUI_FINISHPAGE_SHOWREADME_FUNCTION LaunchReadme
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; ----- Install -----
Section "ARGUS (required)" SecMain
  SectionIn RO
  SetOutPath "$INSTDIR"

  ; Embed + extract the binary from dist/.
  File /oname=${APP_EXE} "..\dist\argus-windows-amd64.exe"

  WriteRegStr HKCU "Software\${APP_NAME}" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "Software\${APP_NAME}" "Version" "${APP_VERSION}"

  Call AddToUserPath

  ; Programs-and-Features uninstall entry.
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "DisplayName" "${APP_NAME} ${APP_VERSION}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "DisplayIcon" "$INSTDIR\${APP_EXE}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "Publisher" "${APP_PUBLISHER}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "URLInfoAbout" "${APP_URL}"
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "NoModify" 1
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "NoRepair" 1

  WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

Function LaunchReadme
  ExecShell "open" "${APP_URL}"
FunctionEnd

; ----- AddToUserPath -----
; Appends $INSTDIR to HKCU\Environment\Path (REG_EXPAND_SZ) if not
; already present. Broadcasts WM_WININICHANGE so running processes
; pick up the new value without requiring logoff.
Function AddToUserPath
  Push $0
  Push $1

  ReadRegStr $0 HKCU "Environment" "Path"

  ; Substring check via StrFunc's StrStr. Returns "" if needle not
  ; found, else returns a substring starting at the match.
  ${StrStr} $1 "$0" "$INSTDIR"
  ${If} $1 != ""
    DetailPrint "$INSTDIR already on user PATH; skipping."
    Goto done
  ${EndIf}

  ${If} $0 == ""
    StrCpy $0 "$INSTDIR"
  ${Else}
    StrCpy $0 "$0;$INSTDIR"
  ${EndIf}

  WriteRegExpandStr HKCU "Environment" "Path" "$0"
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=1000

  DetailPrint "Added $INSTDIR to user PATH."

done:
  Pop $1
  Pop $0
FunctionEnd

; ----- Uninstall -----
Section "Uninstall"
  Call un.RemoveFromUserPath

  Delete "$INSTDIR\${APP_EXE}"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"

  DeleteRegKey HKCU "Software\${APP_NAME}"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}"
SectionEnd

; Uninstall-side StrFunc activation (needed for the un.StrStr).
${UnStrStr}

Function un.RemoveFromUserPath
  Push $0
  Push $1
  Push $2

  ReadRegStr $0 HKCU "Environment" "Path"
  ${If} $0 == ""
    Goto done
  ${EndIf}

  ; Find our dir in the PATH.
  ${UnStrStr} $1 "$0" "$INSTDIR"
  ${If} $1 == ""
    ; Not present — nothing to do.
    Goto done
  ${EndIf}

  ; Rebuild PATH without $INSTDIR. Simplest correct approach: split
  ; by ";", filter, re-join. WordFunc has macros, but for robustness
  ; we do it manually: find either ";$INSTDIR" or "$INSTDIR;" or
  ; the bare "$INSTDIR" and splice it out.
  ${UnStrStr} $1 "$0" ";$INSTDIR;"
  ${If} $1 != ""
    ; Case: ...;$INSTDIR;...
    Push $0
    Push ";$INSTDIR;"
    Push ";"
    Call un.StrReplace
    Pop $0
    Goto write
  ${EndIf}

  ${UnStrStr} $1 "$0" ";$INSTDIR"
  ${If} $1 != ""
    ; Case: ...;$INSTDIR (at end)
    Push $0
    Push ";$INSTDIR"
    Push ""
    Call un.StrReplace
    Pop $0
    Goto write
  ${EndIf}

  ${UnStrStr} $1 "$0" "$INSTDIR;"
  ${If} $1 != ""
    ; Case: $INSTDIR;... (at start)
    Push $0
    Push "$INSTDIR;"
    Push ""
    Call un.StrReplace
    Pop $0
    Goto write
  ${EndIf}

  ; Case: bare $INSTDIR (only entry)
  StrCpy $0 ""

write:
  WriteRegExpandStr HKCU "Environment" "Path" "$0"
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=1000

done:
  Pop $2
  Pop $1
  Pop $0
FunctionEnd

; un.StrReplace — simple string replace for the uninstaller. Takes
; haystack / needle / replacement on the stack, leaves result on stack.
Function un.StrReplace
  Exch $R2 ; replacement
  Exch
  Exch $R1 ; needle
  Exch 2
  Exch $R0 ; haystack
  Push $R3 ; accumulator
  Push $R4 ; position
  Push $R5 ; chunk

  StrCpy $R3 ""
  StrLen $R4 $R1
  loop:
    ${UnStrStr} $R5 "$R0" "$R1"
    ${If} $R5 == ""
      StrCpy $R3 "$R3$R0"
      Goto done
    ${EndIf}
    ; Length of the non-matching prefix of $R0.
    StrLen $0 "$R0"
    StrLen $1 "$R5"
    IntOp $0 $0 - $1
    StrCpy $2 "$R0" $0
    StrCpy $R3 "$R3$2$R2"
    StrCpy $R0 "$R5" "" $R4
    Goto loop
  done:

  Pop $R5
  Pop $R4
  Pop $R3
  Pop $R0
  Exch
  Pop $R1
  Exch
  Pop $R2
  Push $R3
FunctionEnd
