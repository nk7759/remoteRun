# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run

```powershell
# Debug 빌드
dotnet build

# Release 빌드
dotnet build -c Release

# 실행 (Release)
.\bin\Release\net48\remoteRun.exe
```

출력 바이너리: `bin\{Debug|Release}\net48\remoteRun.exe`  
대상 프레임워크: .NET Framework 4.8 (`net48`)

## 연결 문자열 DPAPI 암호화 (최초 1회)

```powershell
# 평문 연결 문자열 → encrypted:... 값 생성
remoteRun.exe --encrypt-conn "server=...;uid=...;pwd=...;database=..."
# 출력값을 App.config connectionString에 "encrypted:<출력값>" 형태로 입력
```

## 아키텍처

이 프로그램은 **WMI를 통해 원격 Windows 호스트에서 프로세스를 실행**하는 단일 목적 콘솔 앱입니다.

```
Main()
 ├─ GetDecryptedAdminPassword()  → ezResource DB에서 AD 계정/암호 조회 후 AES-256 복호화
 └─ fun_RemoteComputerEtcInfo()  → WMI Win32_Process.Create() 로 원격 EXE 실행
                                   오류 시 WriteTextLog() → 로컬 파일 + DSOM DB (SP_AD_LOG_SAVE)
```

### 설정 우선순위 (`SecureConfig`)

| 항목 | 1순위 | 2순위 | 3순위 |
|------|-------|-------|-------|
| DB 연결 문자열 | 환경 변수 `{NAME}_CONN` (예: `EZRESOURCE_CONN`) | App.config `connectionStrings` (평문) | App.config `connectionStrings` (`encrypted:` DPAPI) |
| AES 키 | 환경 변수 `REMOTERUN_AES_KEY` | App.config `appSettings["REMOTERUN_AES_KEY"]` | — |

### 암호화 레이어

- **DB 비밀번호 (AD 계정)**: AES-256-CBC, 키는 `SecureConfig.GetAesKeyBytes()`, IV = 키 앞 16바이트
- **App.config 연결 문자열**: Windows DPAPI (`LocalMachine` 스코프) — `DpapiHelper` 클래스 사용

### 원격 실행 대상

- 대상 IP: `152.149.148.91` (현재 하드코딩)
- 실행 EXE: `C:\AD_BAT\RUN\ADVendorIDProcess.exe`
- 인증: NTLM (`ntlmdomain:`)

### 로그

- 로컬 파일: `C:\AD_BAT\LOG\ADVendorIDProcess_<dd>.txt` (일별 순환)
- DB: `DSOM` DB의 `SP_AD_LOG_SAVE` 저드 프로시저 (`@vGubn`, `@vEventPos`, `@vContents`)
