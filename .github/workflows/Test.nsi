!define /ifndef TARGET "x86-unicode"
!define /ifndef FILEPREFIX ""
!define /ifndef FILESUFFIX""

Target ${TARGET}    ; "x86-unicode", "amd64-unicode"

Name    "${FILEPREFIX}Test_${TARGET}${FILESUFFIX}"
OutFile "${FILEPREFIX}Test_${TARGET}${FILESUFFIX}.exe"
InstallDir "$TEMP"  ; no files are dropped
ManifestDPIAware true
RequestExecutionLevel user
ShowInstDetails show

!include /nonfatal "ModernXL.nsh"   ; available in https://github.com/negrutiu/nsis
!include "MUI2.nsh"
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\nsis-menu.ico"

;!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${__FILE__}"
!insertmacro MUI_PAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

!include nsArray.nsh

Section nsArray
    DetailPrint 'Calling plugin "nsArray" ...'

    nsArray::Split MyArray a|b|c|d |
    ${nsArray_ToString} MyArray $R0
    DetailPrint $R0

    ${nsArray_Copy} MyArray MyArrayCopy
    ${nsArray_ToString} MyArrayCopy $R0
    DetailPrint $R0

    ${nsArray_CopyKeys} MyArray MyArrayKeys
    ${nsArray_ToString} MyArrayKeys $R0
    DetailPrint $R0

    ${ForEachIn} MyArray $R0 $R1
        DetailPrint `MyArray[$R0] => $R1`
    ${Next}

    ${ForEachIn} MyArray99 $R0 $R1
        DetailPrint `MyArray[$R0] => $R1`
    ${Next}

    ${ForEachInReverse} MyArray $R0 $R1
        DetailPrint `MyArray[$R0] => $R1`
    ${Next}

    DetailPrint '--------------------------------------------------'
SectionEnd


Section NScurl
    DetailPrint 'Calling plugin "NScurl" ...'

    NScurl::http \
            POST \
            https://httpbin.org/post?param1=value1&param2=value2 \
            memory \
            /header "Content-Type: application/json" \
            /data '{ "number_of_the_beast" : 666 }' \
            /referer "https://test.com" \
            /insist \
            /cancel \
            /return "@id@" \
            /end
    Pop $0  ; transfer ID

    NScurl::query /id $0 "@method@ @url@ => @errortype@ @errorcode@, @filesize@, @timeelapsed_ms@ms"
    Pop $1
    DetailPrint $1

    NScurl::query /id $0 "@recvheaders@"
    Pop $1
    DetailPrint "Headers: $1"

    NScurl::query /id $0 "@recvdata@"
    Pop $1
    DetailPrint "Response: $1"

    DetailPrint '--------------------------------------------------'
SectionEnd


Section -Notice
    DetailPrint '-- This is a demo project'
    DetailPrint '-- No files and/or registry keys were modified'
SectionEnd