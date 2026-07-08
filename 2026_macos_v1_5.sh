#!/bin/bash
# =====================================================================
# macOS PC Security Check Script
# Version   : 1.5
# Copyright : Kairos Lab
# 변경사항(v1.5): GitHub Actions macOS 14/15/26 실기기 검증 결과 반영
#   - PC-13/14: 백신 탐지 오탐 수정 (ESET가 'PasscodeSettingsSubscriber' 등
#     시스템 프로세스에 부분문자열 매칭되어 거짓 GOOD 발생 -> Apple 시스템 경로 제외 +
#     실제 데몬/프로세스명·앱번들명 정밀 매칭 + LaunchDaemon 흔적 보조 확인)
#   - PC-02: 복잡성 판정 정교화 (단순 길이 정규식 '.{4,}'를 복잡성으로 오인하던 문제 수정,
#     문자클래스/룩어헤드/requires* 만 복잡성 인정, macOS 기본정책만 존재 시 취약 처리)
# 기준      : KISA 2026 주요정보통신기반시설 기술적 취약점 상세가이드 PC-01~PC-18 판단기준 대조
#             점검 '대상'이 macOS에 존재하지 않는 항목만 N/A, 통제목적이 공통인 항목은 판정
# 변경사항  : v1.4:
#             - PC-02(복잡성 암호정책) N/A -> 자동 점검 구현 (pwpolicy/account policy)
#             - PC-11(EOL/지원 버전) N/A -> 자동 점검 구현 (macOS major 버전 비교)
#             - PC-06(상용 메신저) N/A -> 수동 전환
#             - PC-08(멀티부팅) N/A -> 수동 전환
#             - PC-15 Stealth Mode 필수기준 -> 권고로 하향 (가이드는 방화벽 ON=양호)
#             - PC-01/PC-16 값 미확인 시 취약 -> 수동 (증거부재 원칙)
#             - PC-16 askForPasswordDelay<=300 조건 제거 (가이드 미포함), 대기시간 10분 기준 유지
#             - PC-04 SharePoints 잔존 레코드 오탐 제거 (sharing -l/smbd 기준 판정)
#             유지 N/A: PC-03(복구콘솔) PC-05(Win서비스) PC-07(NTFS) PC-09(IE임시파일) PC-17(Autorun)
# 실행      : chmod +x 2026_macos_v1.4.sh && sudo ./2026_macos_v1.4.sh
# =====================================================================

export LANG=C
export LC_ALL=C

GOOD_COUNT=0
VULN_COUNT=0
MANUAL_COUNT=0
NA_COUNT=0
TOTAL_COUNT=0

PASSWORD_MAX_DAYS=90
SCREEN_SAVER_MAX_SECONDS=600          # PC-16 화면보호기 대기시간 기준(10분)
PASSWORD_MIN_LENGTH=8                 # PC-02 최소 암호 길이 기준
SCRIPT_VERSION="1.5"
COPYRIGHT="Kairos Lab"

# PC-11: Apple 보안 업데이트 지원 대상 macOS major 버전 (통상 최신 포함 3개)
# ※ 점검 시점 기준으로 관리자가 갱신할 것 (예시: 2026년 기준 26/15/14)
MACOS_SUPPORTED_MAJORS="26 15 14"

HOSTNAME_VAL="$(scutil --get ComputerName 2>/dev/null)"
[ -z "$HOSTNAME_VAL" ] && HOSTNAME_VAL="$(hostname 2>/dev/null)"
[ -z "$HOSTNAME_VAL" ] && HOSTNAME_VAL="unknown"

IP_ADDR="$(ipconfig getifaddr en0 2>/dev/null)"
[ -z "$IP_ADDR" ] && IP_ADDR="$(ipconfig getifaddr en1 2>/dev/null)"
[ -z "$IP_ADDR" ] && IP_ADDR="$(ifconfig 2>/dev/null | awk '/inet / && $2 != "127.0.0.1" {print $2; exit}')"
[ -z "$IP_ADDR" ] && IP_ADDR="unknown"

DATE_TAG="$(date '+%Y%m%d_%H%M%S')"
CHECK_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
OS_VERSION="$(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null) ($(sw_vers -buildVersion 2>/dev/null))"
REPORT_FILE="${HOSTNAME_VAL}_${IP_ADDR}_mac_${DATE_TAG}.txt"
REPORT_FILE="$(echo "$REPORT_FILE" | sed 's/[[:space:]\/\\:*?"<>|]/_/g')"

exec > >(tee "$REPORT_FILE") 2>&1

print_header() {
cat <<EOT
==================== macOS PC Security Check Report ====================
Check Date : $CHECK_DATE
OS 버전    : $OS_VERSION
Hostname   : $HOSTNAME_VAL / IP: $IP_ADDR
Scan Mode  : normal
Report File: $REPORT_FILE
Version    : $SCRIPT_VERSION
Copyright  : $COPYRIGHT
=============================================================
EOT
}

begin_check() {
    local no="$1"
    local code="$2"
    local title="$3"
    echo ""
    echo "##################################################################"
    echo "=================================================================="
    echo "[$code] $title"
    echo "=================================================================="
    echo "[$no-START]"
}

end_check() {
    local no="$1"
    echo "[$no-END]"
}

add_count() {
    local result="$1"
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    case "$result" in
        GOOD|SAFE) GOOD_COUNT=$((GOOD_COUNT + 1)) ;;
        VULNERABLE) VULN_COUNT=$((VULN_COUNT + 1)) ;;
        MANUAL) MANUAL_COUNT=$((MANUAL_COUNT + 1)) ;;
        "N/A") NA_COUNT=$((NA_COUNT + 1)) ;;
        *) MANUAL_COUNT=$((MANUAL_COUNT + 1)) ;;
    esac
}

print_result() {
    local code="$1"
    local result="$2"
    local action="$3"
    echo ""
    echo "[$code] Result : $result"
    if [ -n "$action" ]; then
        echo "[조치사항]"
        echo "$action"
    fi
    add_count "$result"
}

get_console_user() {
    stat -f '%Su' /dev/console 2>/dev/null
}

print_na_macos() {
    local code="$1"
    echo ""
    echo "[현황]"
    echo "1. 버전 확인"
    echo "   System Version: $(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null) ($(sw_vers -buildVersion 2>/dev/null))"
    echo "   Kernel Version: $(uname -r 2>/dev/null)"
    print_result "$code" "N/A" "macOS 환경에서는 해당 Windows 전용 점검 항목이 적용되지 않으므로 해당사항 없음."
}

# 알려진 백신/EDR 탐지 패턴
# 주의: 짧은 토큰(ESET,V3 등)의 부분문자열 오탐 방지를 위해 '실제 데몬/프로세스명'과
#       '벤더 고유 식별자' 위주로 구성하고, Apple 시스템 경로(/System, /usr/libexec)는 제외한다.
#   예) ESET가 'PasscodeSettingsSubscriber'의 codeSettings에 오탐되던 문제 해결
AV_PROC_PATTERN="falcond|com\.crowdstrike|CrowdStrike Falcon|wdavdaemon|com\.microsoft\.wdav|Microsoft Defender|sentineld|SentinelAgent|com\.sentinelone|SophosScanD|com\.sophos|Sophos Endpoint|esets_daemon|com\.eset|ESET Endpoint|RTProtectionDaemon|com\.malwarebytes|AhnLabV3|com\.ahnlab|AhnLab|/V3\.app|Bitdefender|com\.bitdefender|TmccMac|com\.trendmicro|masvc|com\.mcafee|kavsvc|com\.kaspersky|SymDaemon|com\.symantec|com\.norton"
# 앱 번들 정확 탐지용 (부분문자열 남용 방지)
AV_APP_PATTERN='*AhnLab*.app|V3.app|Falcon.app|*Microsoft Defender*.app|*Sophos*.app|*SentinelOne*.app|*ESET*.app|*Bitdefender*.app|*Malwarebytes*.app|*McAfee*.app|*Norton*.app'

print_header

# ---------------------------------------------------------------------
# PC-01 패스워드의 주기적 변경
# ---------------------------------------------------------------------
begin_check "1" "PC-01" "패스워드의 주기적 변경"
echo "패스워드 최대 사용기간이 ${PASSWORD_MAX_DAYS}일 이하로 설정되어 있는지 점검"
echo ""
echo "[현황]"
CONSOLE_USER="$(get_console_user)"
echo "콘솔 사용자: ${CONSOLE_USER:-미확인}"
PW_GLOBAL="$(pwpolicy -getglobalpolicy 2>/dev/null)"
PW_ACCOUNT=""
if [ -n "$CONSOLE_USER" ] && [ "$CONSOLE_USER" != "root" ]; then
    PW_ACCOUNT="$(pwpolicy -u "$CONSOLE_USER" -getpolicy 2>/dev/null)"
fi
PW_ALL="$PW_GLOBAL $PW_ACCOUNT"
echo "pwpolicy(global): ${PW_GLOBAL:-미설정 또는 확인 불가}"
MAX_MINUTES="$(echo "$PW_ALL" | tr ' ' '\n' | awk -F= '/maxMinutesUntilChangePassword/ {print $2; exit}')"
if [ -n "$MAX_MINUTES" ]; then
    MAX_DAYS=$((MAX_MINUTES / 1440))
    echo "maxMinutesUntilChangePassword: $MAX_MINUTES (${MAX_DAYS}일)"
    if [ "$MAX_DAYS" -le "$PASSWORD_MAX_DAYS" ]; then
        print_result "PC-01" "GOOD" ""
    else
        print_result "PC-01" "VULNERABLE" "패스워드 최대 사용기간을 ${PASSWORD_MAX_DAYS}일 이하로 설정해야 함."
    fi
else
    echo "maxMinutesUntilChangePassword: 미설정 또는 확인 불가"
    print_result "PC-01" "MANUAL" "로컬 pwpolicy에서 최대 사용기간이 확인되지 않음(최신 macOS pwpolicy deprecated 또는 MDM 통제 가능). MDM 구성 프로파일/계정정책 증적으로 ${PASSWORD_MAX_DAYS}일 이하 설정 여부 수동 확인 필요."
fi
end_check "1"

# ---------------------------------------------------------------------
# PC-02 패스워드 정책이 해당 기관의 보안 정책에 적합하게 설정
# ---------------------------------------------------------------------
begin_check "2" "PC-02" "패스워드 정책이 해당 기관의 보안 정책에 적합하게 설정"
echo "패스워드 복잡성 정책(최소 길이 및 문자조합) 설정 여부 점검"
echo ""
echo "[현황]"
GLOBAL_POLICY="$(pwpolicy -getglobalpolicy 2>/dev/null)"
ACCOUNT_POLICY="$(pwpolicy -getaccountpolicies 2>/dev/null)"
POLICY_ALL="$GLOBAL_POLICY
$ACCOUNT_POLICY"
echo "1. pwpolicy 전역 정책"
echo "${GLOBAL_POLICY:-미설정 또는 확인 불가}"

# 최소 길이 추출 (global: minChars= / account XML: minimumLength / 정규식 matches ...{N,})
MIN_LEN="$(echo "$GLOBAL_POLICY" | tr ' ' '\n' | awk -F= '/minChars/ {print $2; exit}')"
if [ -z "$MIN_LEN" ]; then
    MIN_LEN="$(echo "$ACCOUNT_POLICY" | grep -Eo 'minimumLength[^0-9]*[0-9]+' | grep -Eo '[0-9]+' | head -n1)"
fi
if [ -z "$MIN_LEN" ]; then
    # 정규식 수량자 '{N,}' 의 N만 추출 (문자클래스 [0-9] 안의 숫자를 길이로 오추출하지 않도록).
    # 여러 수량자가 있으면 가장 큰 값을 유효 최소길이로 간주.
    MIN_LEN="$(echo "$ACCOUNT_POLICY" | grep -Eo '\{[0-9]+' | grep -Eo '[0-9]+' | sort -n | tail -1)"
fi

# 실제 문자조합 복잡성만 인정: 문자클래스([A-Z]/[a-z]/[0-9]), 룩어헤드((?=), requires* 플래그
# 주의: 기본 정책 '^$|.{4,}+'처럼 단순 길이만 있는 정규식은 복잡성으로 인정하지 않음
COMPLEXITY_REAL=0
echo "$POLICY_ALL" | grep -Eqi 'requiresAlpha=1|requiresNumeric=1|requiresSymbol=1|requiresMixedCase=1|\(\?=|\[A-Z\]|\[a-z\]|\[0-9\]|\[[^]]*[A-Za-z0-9][^]]*\]' && COMPLEXITY_REAL=1

# 기본(factory) 정책만 존재하는지: com.apple.defaultpasswordpolicy 외 다른 정책 식별자가 없으면 기본 정책만 있음
DEFAULT_ONLY=0
if echo "$ACCOUNT_POLICY" | grep -q 'com.apple.defaultpasswordpolicy'; then
    OTHER_POLICY="$(echo "$ACCOUNT_POLICY" | grep -Ei '<key>policyIdentifier</key>' -A1 2>/dev/null | grep -Eo 'com\.[a-zA-Z0-9._]+' | grep -v 'com.apple.defaultpasswordpolicy')"
    [ -z "$OTHER_POLICY" ] && [ "$COMPLEXITY_REAL" -eq 0 ] && DEFAULT_ONLY=1
fi

echo ""
echo "2. 복잡성 판정 근거"
echo "최소 길이(minChars/minimumLength/정규식): ${MIN_LEN:-미확인}"
echo "실제 문자조합 복잡성: $([ "$COMPLEXITY_REAL" -eq 1 ] && echo '있음' || echo '없음/미확인')"
echo "기본(factory) 비밀번호 정책만 존재: $([ "$DEFAULT_ONLY" -eq 1 ] && echo '예' || echo '아니오')"
echo "기준: 2종 이상 조합+10자 이상 또는 3종 이상 조합+8자 이상 (최소 ${PASSWORD_MIN_LENGTH}자, 문자조합 필수)"

if [ -z "$GLOBAL_POLICY" ] && [ -z "$ACCOUNT_POLICY" ]; then
    print_result "PC-02" "MANUAL" "로컬 pwpolicy 정책이 확인되지 않음. MDM 구성 프로파일(비밀번호 정책)로 통제 중일 수 있으므로 프로파일 증적 확인 필요."
elif [ "$DEFAULT_ONLY" -eq 1 ]; then
    print_result "PC-02" "VULNERABLE" "macOS 기본 비밀번호 정책만 적용되어 있어(길이 최소 ${MIN_LEN:-4}자 수준, 문자조합 복잡성 미설정) 복잡성 기준을 만족하지 않음. pwpolicy 또는 MDM 프로파일로 길이·문자조합 복잡성 정책 설정 필요."
elif [ -n "$MIN_LEN" ] && [ "$MIN_LEN" -ge "$PASSWORD_MIN_LENGTH" ] 2>/dev/null && [ "$COMPLEXITY_REAL" -eq 1 ]; then
    print_result "PC-02" "GOOD" ""
elif [ -n "$MIN_LEN" ] && [ "$MIN_LEN" -lt "$PASSWORD_MIN_LENGTH" ] 2>/dev/null; then
    print_result "PC-02" "VULNERABLE" "최소 암호 길이가 ${PASSWORD_MIN_LENGTH}자 미만으로 설정됨. 길이 및 문자조합 복잡성 정책을 기관 보안정책에 맞게 강화 필요."
elif [ -n "$MIN_LEN" ] && [ "$COMPLEXITY_REAL" -eq 0 ] 2>/dev/null; then
    print_result "PC-02" "VULNERABLE" "길이(${MIN_LEN}자) 정책은 있으나 문자조합 복잡성 정책이 확인되지 않음. 영문·숫자·특수문자 조합 복잡성 정책 설정 필요."
else
    print_result "PC-02" "MANUAL" "복잡성 정책 충족 여부를 자동으로 확정하기 어려움(길이=${MIN_LEN:-미확인}, 복잡성=$([ "$COMPLEXITY_REAL" -eq 1 ] && echo '있음' || echo '미확인')). MDM 프로파일 또는 pwpolicy -getaccountpolicies 결과로 복잡성 정책 수동 확인 필요."
fi
end_check "2"

# ---------------------------------------------------------------------
# PC-03 복구 콘솔 자동 로그온 금지 설정
# ---------------------------------------------------------------------
begin_check "3" "PC-03" "복구 콘솔 자동 로그온 금지 설정"
print_na_macos "PC-03"
end_check "3"

# ---------------------------------------------------------------------
# PC-04 공유 폴더 제거
# ---------------------------------------------------------------------
begin_check "4" "PC-04" "공유 폴더 제거"
echo "macOS 공유 폴더 및 파일 공유 서비스 활성화 여부 점검"
echo ""
echo "[현황]"
SHARE_LIST=""
SHARE_POINT_LIST=""
if command -v sharing >/dev/null 2>&1; then
    SHARE_LIST="$(sharing -l 2>/dev/null)"
fi
SHARE_POINT_LIST="$(dscl . -list /SharePoints 2>/dev/null)"
SMB_PROCESS="$(pgrep -x smbd 2>/dev/null)"
SMB_STATUS="$(launchctl print system/com.apple.smbd 2>/dev/null | head -n 8)"
echo "1. 공유 폴더 목록 확인"
if [ -n "$SHARE_LIST" ]; then
    echo "$SHARE_LIST"
elif [ -n "$SHARE_POINT_LIST" ]; then
    echo "$SHARE_POINT_LIST"
else
    echo "공유 폴더 확인 결과 없음"
fi
echo ""
echo "2. SMB 서비스 상태"
if [ -n "$SMB_PROCESS" ]; then
    echo "smbd process: running ($SMB_PROCESS)"
elif [ -n "$SMB_STATUS" ]; then
    echo "$SMB_STATUS"
else
    echo "com.apple.smbd: not loaded"
fi
# 판정: SharePoints 목록 존재만으로는 취약이 아님(공유 OFF 후에도 레코드 잔존).
#       실제 공유 활성(sharing -l의 shared 플래그) 또는 smbd 구동 여부로 판정.
SHARE_ACTIVE=0
echo "$SHARE_LIST" | grep -Eqi "shared:[[:space:]]*1|guest access:[[:space:]]*1" && SHARE_ACTIVE=1
[ -n "$SMB_PROCESS" ] && SHARE_ACTIVE=1
if [ "$SHARE_ACTIVE" -eq 1 ]; then
    print_result "PC-04" "VULNERABLE" "파일 공유(SMB) 서비스 또는 활성 공유가 존재하므로 불필요 시 공유 해제 필요. 업무상 필요한 공유인 경우 접근권한 및 승인 증적 확인 필요."
else
    print_result "PC-04" "GOOD" "등록된 공유 지점(SharePoints) 레코드가 남아있을 수 있으나 파일 공유 서비스가 비활성 상태이므로 양호로 판단함."
fi
end_check "4"

# ---------------------------------------------------------------------
# PC-05 항목의 불필요한 서비스 제거
# ---------------------------------------------------------------------
begin_check "5" "PC-05" "항목의 불필요한 서비스 제거"
print_na_macos "PC-05"
end_check "5"

# ---------------------------------------------------------------------
# PC-06 비인가 상용 메신저 사용 금지
# ---------------------------------------------------------------------
begin_check "6" "PC-06" "Windows Messenger(MSN, .NET 메신저 등)와 같은 상용 메신저의 사용 금지"
echo "상용 메신저(카카오톡, 네이트온, Skype, Telegram, Line, WeChat 등) 설치 여부 점검"
echo ""
echo "[현황]"
MSG_PATTERN="KakaoTalk|NateOn|Skype|Telegram|Line|WeChat|QQ|Discord"
echo "1. 메신저 응용프로그램 확인"
MSG_APPS="$(find /Applications -maxdepth 2 -iname '*.app' 2>/dev/null | grep -Ei "$MSG_PATTERN" | head -n 20)"
if [ -n "$MSG_APPS" ]; then
    echo "$MSG_APPS"
else
    echo "알려진 상용 메신저 응용프로그램 확인되지 않음(/Applications 기준)"
fi
print_result "PC-06" "MANUAL" "상용 메신저의 업무 인가 여부는 기관 정책에 따라 판단해야 하며, 사용자 홈 디렉터리 설치분은 스크립트로 완전 탐지되지 않음. 비인가 상용 메신저 설치·사용 여부를 정책 기준으로 수동 확인 필요."
end_check "6"

# ---------------------------------------------------------------------
# PC-07 파일 시스템을 NTFS로 포맷
# ---------------------------------------------------------------------
begin_check "7" "PC-07" "파일 시스템을 NTFS로 포맷"
print_na_macos "PC-07"
end_check "7"

# ---------------------------------------------------------------------
# PC-08 다른 OS로 멀티 부팅 금지
# ---------------------------------------------------------------------
begin_check "8" "PC-08" "다른 OS로 멀티 부팅 금지"
echo "멀티 부팅(다른 OS 설치) 여부 점검"
echo ""
echo "[현황]"
echo "1. 타 OS 파티션 흔적 확인 (diskutil)"
OTHER_OS_PART="$(diskutil list 2>/dev/null | grep -Ei 'Microsoft|Windows|BOOTCAMP|Linux|EFI System|NTFS|Windows_NTFS')"
if [ -n "$OTHER_OS_PART" ]; then
    echo "$OTHER_OS_PART"
else
    echo "BootCamp/Windows/Linux 관련 파티션 미발견"
fi
echo ""
echo "2. 부팅 관리 정보 (bless)"
BLESS_INFO="$(bless --info 2>/dev/null | head -n 6)"
echo "${BLESS_INFO:-확인 불가}"
print_result "PC-08" "MANUAL" "다중 부팅 여부는 파티션 구성 및 부팅 관리자 확인이 필요하므로 수동 판단 필요. 위 diskutil 결과에 타 OS(BootCamp/Windows/Linux) 파티션이 존재하는지 확인. (EFI System 파티션은 정상 구성일 수 있음)"
end_check "8"

# ---------------------------------------------------------------------
# PC-09 브라우저 종료 시 임시 인터넷 파일 폴더 내용 삭제
# ---------------------------------------------------------------------
begin_check "9" "PC-09" "브라우저 종료 시 임시 인터넷 파일 폴더 내용 삭제"
print_na_macos "PC-09"
end_check "9"

# ---------------------------------------------------------------------
# PC-10 HOT FIX 등 최신 보안패치
# ---------------------------------------------------------------------
begin_check "10" "PC-10" "HOT FIX 등 최신 보안패치"
echo "macOS 소프트웨어 업데이트 확인 결과를 점검"
echo ""
echo "[현황]"
echo "1. 버전 확인"
echo "   System Version: $(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null) ($(sw_vers -buildVersion 2>/dev/null))"
echo "   Kernel Version: $(uname -r 2>/dev/null)"
echo ""
echo "2. 소프트웨어 업데이트 확인"
UPDATE_LIST="$(softwareupdate -l 2>&1 | head -n 60)"
echo "$UPDATE_LIST"
if echo "$UPDATE_LIST" | grep -Eqi "No new software available|No new software available\."; then
    print_result "PC-10" "GOOD" ""
elif echo "$UPDATE_LIST" | grep -Eqi "Software Update found|recommended|\* Label:|Title:"; then
    print_result "PC-10" "VULNERABLE" "사용 가능한 macOS 보안/시스템 업데이트가 존재하므로 최신 업데이트 적용 필요."
else
    print_result "PC-10" "MANUAL" "softwareupdate 결과를 명확히 해석할 수 없음. 시스템 설정 > 일반 > 소프트웨어 업데이트 화면에서 최신 업데이트 여부 확인 필요."
fi
end_check "10"

# ---------------------------------------------------------------------
# PC-11 지원이 종료되지 않은 Windows OS Build 적용
# ---------------------------------------------------------------------
begin_check "11" "PC-11" "지원이 종료되지 않은 OS 버전(빌드) 적용"
echo "지원 종료(EOL)되지 않은 macOS 버전 사용 여부 점검"
echo ""
echo "[현황]"
PROD_VER="$(sw_vers -productVersion 2>/dev/null)"
BUILD_VER="$(sw_vers -buildVersion 2>/dev/null)"
MAJOR_VER="$(echo "$PROD_VER" | cut -d. -f1)"
echo "1. 버전 확인"
echo "   macOS Version : ${PROD_VER:-미확인} (build ${BUILD_VER:-미확인})"
echo "   Major Version : ${MAJOR_VER:-미확인}"
echo "   지원 대상 major 목록(관리자 기준): $MACOS_SUPPORTED_MAJORS"
if [ -z "$MAJOR_VER" ]; then
    print_result "PC-11" "MANUAL" "macOS 버전을 확인할 수 없음. 버전 확인 후 Apple 보안 업데이트 지원 대상(EOL) 여부 수동 확인 필요."
elif echo " $MACOS_SUPPORTED_MAJORS " | grep -q " $MAJOR_VER "; then
    print_result "PC-11" "GOOD" ""
else
    print_result "PC-11" "VULNERABLE" "현재 macOS(major $MAJOR_VER)가 지원 대상 목록($MACOS_SUPPORTED_MAJORS)에 없어 EOL 가능성이 있으므로 지원되는 최신 버전으로 업그레이드 필요. 지원 목록은 점검 시점 기준 Apple 공지로 재확인 권장."
fi
end_check "11"

# ---------------------------------------------------------------------
# PC-12 Windows 자동 로그인 점검
# ---------------------------------------------------------------------
begin_check "12" "PC-12" "Windows 자동 로그인 점검"
echo "macOS 자동 로그인 설정 여부 점검"
echo ""
echo "[현황]"
AUTO_LOGIN_USER="$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null)"
if [ -z "$AUTO_LOGIN_USER" ]; then
    echo "autoLoginUser: 미설정"
    print_result "PC-12" "GOOD" ""
else
    echo "autoLoginUser: $AUTO_LOGIN_USER"
    print_result "PC-12" "VULNERABLE" "자동 로그인이 설정되어 있으므로 비활성화 필요."
fi
end_check "12"

# ---------------------------------------------------------------------
# PC-13 바이러스 백신 프로그램 설치 및 주기적 업데이트
# ---------------------------------------------------------------------
begin_check "13" "PC-13" "바이러스 백신 프로그램 설치 및 주기적 업데이트"
echo "macOS 백신/EDR 설치 및 실행 여부 점검"
echo ""
echo "[현황]"
echo "1. 프로세스 확인 (Apple 시스템 경로 제외)"
# /System, /usr/libexec 등 Apple 기본 프로세스를 먼저 제외한 뒤 백신/EDR 패턴 매칭 (부분문자열 오탐 방지)
AV_PS="$(ps ax 2>/dev/null | grep -v grep | grep -vaE '/System/|/usr/libexec/|/Library/Apple/' | grep -Ea "$AV_PROC_PATTERN" | head -n 20)"
if [ -n "$AV_PS" ]; then
    echo "$AV_PS"
else
    echo "알려진 백신/EDR 프로세스 확인되지 않음"
fi
echo ""
echo "2. 응용프로그램 확인"
# 앱 번들명을 정확히 지정 (예: 'V3.app', 'ESET*.app') — '*V3*' 같은 광범위 매칭 지양
AV_APPS="$(find /Applications -maxdepth 2 \( \
    -iname 'AhnLab*.app' -o -iname 'V3.app' -o -iname 'V3 *.app' -o \
    -iname 'Falcon.app' -o -iname 'Microsoft Defender*.app' -o -iname 'Sophos*.app' -o \
    -iname 'SentinelOne*.app' -o -iname 'ESET*.app' -o -iname 'Bitdefender*.app' -o \
    -iname 'Malwarebytes*.app' -o -iname 'McAfee*.app' -o -iname 'Norton*.app' -o \
    -iname 'Trend Micro*.app' \) 2>/dev/null | head -n 20)"
# 벤더 설치 흔적(LaunchDaemon/지원 폴더)도 보조 근거로 확인
AV_DAEMON="$(ls /Library/LaunchDaemons/ 2>/dev/null | grep -Eai 'crowdstrike|sentinel|sophos|eset|malwarebytes|ahnlab|bitdefender|trendmicro|mcafee|kaspersky|symantec|wdav' | head -n 10)"
if [ -n "$AV_APPS" ]; then
    echo "$AV_APPS"
else
    echo "알려진 백신/EDR 응용프로그램 확인되지 않음"
fi
[ -n "$AV_DAEMON" ] && echo "LaunchDaemon 흔적: $AV_DAEMON"
if [ -n "$AV_PS" ] || [ -n "$AV_APPS" ] || [ -n "$AV_DAEMON" ]; then
    print_result "PC-13" "GOOD" "백신/EDR 설치 또는 실행 상태가 확인됨. 업데이트 일자는 제품 관리 콘솔에서 추가 확인 권장."
else
    print_result "PC-13" "MANUAL" "스크립트로 알려진 백신/EDR 설치 여부를 확인하지 못함(미탐지). 백신 또는 EDR 설치 및 최신 업데이트 상태 증적 수동 확인 필요."
fi
end_check "13"

# ---------------------------------------------------------------------
# PC-14 바이러스 백신 프로그램에서 제공하는 실시간 감시 기능 활성화
# ---------------------------------------------------------------------
begin_check "14" "PC-14" "바이러스 백신 프로그램에서 제공하는 실시간 감시 기능 활성화"
echo "백신/EDR 실시간 감시 관련 프로세스 실행 여부 점검"
echo ""
echo "[현황]"
echo "1. 프로세스 확인"
if [ -n "$AV_PS" ]; then
    echo "$AV_PS"
    print_result "PC-14" "GOOD" "백신/EDR 관련 프로세스가 실행 중이므로 실시간 감시 기능이 동작 중인 것으로 판단됨. 정확한 실시간 감시 활성화 상태는 제품 콘솔 확인 권장."
else
    echo "알려진 백신/EDR 프로세스 확인되지 않음"
    print_result "PC-14" "MANUAL" "스크립트로 백신/EDR 실시간 감시 상태를 확인하지 못함. 제품 콘솔 또는 관리서버 증적 확인 필요."
fi
end_check "14"

# ---------------------------------------------------------------------
# PC-15 OS에서 제공하는 침입차단 기능 활성화
# ---------------------------------------------------------------------
begin_check "15" "PC-15" "OS에서 제공하는 침입차단 기능 활성화"
echo "macOS Application Firewall 및 Stealth Mode 활성화 여부 점검"
echo ""
echo "[현황]"
FW_STATUS="$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)"
STEALTH_STATUS="$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null)"
echo "1. OS 방화벽 설정 확인"
echo "${FW_STATUS:-Firewall 상태 확인 불가}"
echo "${STEALTH_STATUS:-Stealth Mode 상태 확인 불가}"
# 가이드(PC-15) 기준: 방화벽 '사용'이면 양호. Stealth Mode는 강화 권고사항(필수 아님).
if echo "$FW_STATUS" | grep -qi "disabled"; then
    print_result "PC-15" "VULNERABLE" "macOS 방화벽이 비활성화되어 있으므로 활성화 필요."
elif echo "$FW_STATUS" | grep -qi "enabled"; then
    if echo "$STEALTH_STATUS" | grep -Eqi "disabled|off"; then
        print_result "PC-15" "GOOD" "방화벽이 활성화되어 양호. Stealth Mode는 현재 비활성 상태로, 보안 강화를 위해 활성화 권고(가이드 필수 기준 아님)."
    else
        print_result "PC-15" "GOOD" ""
    fi
else
    print_result "PC-15" "MANUAL" "macOS 방화벽 상태를 확인할 수 없음. 시스템 설정에서 침입차단 기능 활성화 여부 확인 필요."
fi
end_check "15"

# ---------------------------------------------------------------------
# PC-16 화면보호기 대기 시간 설정 및 재시작 시 암호 보호 설정
# ---------------------------------------------------------------------
begin_check "16" "PC-16" "화면보호기 대기 시간 설정 및 재시작 시 암호 보호 설정"
echo "화면보호기 대기시간 및 잠자기/화면보호기 해제 시 암호 요구 설정 여부 점검"
echo ""
echo "[현황]"
CONSOLE_USER="$(get_console_user)"
echo "콘솔 사용자: ${CONSOLE_USER:-미확인}"
ASK_PASS=""
ASK_DELAY=""
IDLE_TIME=""
if [ -n "$CONSOLE_USER" ] && [ "$CONSOLE_USER" != "root" ]; then
    ASK_PASS="$(sudo -u "$CONSOLE_USER" defaults read com.apple.screensaver askForPassword 2>/dev/null)"
    ASK_DELAY="$(sudo -u "$CONSOLE_USER" defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null)"
    IDLE_TIME="$(sudo -u "$CONSOLE_USER" defaults -currentHost read com.apple.screensaver idleTime 2>/dev/null)"
fi
[ -z "$ASK_PASS" ] && ASK_PASS="미확인"
[ -z "$ASK_DELAY" ] && ASK_DELAY="미확인"
[ -z "$IDLE_TIME" ] && IDLE_TIME="미확인"
echo "1. 화면보호기 설정 확인"
echo "askForPassword: $ASK_PASS"
echo "askForPasswordDelay: $ASK_DELAY (참고용, 가이드 판정 기준 아님)"
echo "idleTime: $IDLE_TIME"
echo "기준: 암호 요구 활성화 + 화면보호기 대기시간 ${SCREEN_SAVER_MAX_SECONDS}초(10분) 이하 및 작동"

# 대기시간 상태 (0=Never=미작동, ~600=적정, 초과=취약, 미확인)
if [ "$IDLE_TIME" = "미확인" ]; then
    IDLE_STATE="unknown"
elif [ "$IDLE_TIME" -eq 0 ] 2>/dev/null; then
    IDLE_STATE="never"
elif [ "$IDLE_TIME" -le "$SCREEN_SAVER_MAX_SECONDS" ] 2>/dev/null; then
    IDLE_STATE="ok"
else
    IDLE_STATE="over"
fi
# 암호 요구 상태
case "$ASK_PASS" in
    1) PASS_STATE="on" ;;
    미확인) PASS_STATE="unknown" ;;
    *) PASS_STATE="off" ;;
esac

if [ "$IDLE_STATE" = "unknown" ] && [ "$PASS_STATE" = "unknown" ]; then
    print_result "PC-16" "MANUAL" "화면보호기/잠금 관련 설정 값을 확인할 수 없음(최신 macOS에서 관련 키 미노출 가능). 시스템 설정 > 잠금화면에서 대기시간 10분 이하 및 암호 요구 설정 수동 확인 필요. MDM 통제 시 프로파일 증적 확인."
elif [ "$PASS_STATE" = "on" ] && [ "$IDLE_STATE" = "ok" ]; then
    print_result "PC-16" "GOOD" ""
elif [ "$PASS_STATE" = "off" ] || [ "$IDLE_STATE" = "over" ] || [ "$IDLE_STATE" = "never" ]; then
    print_result "PC-16" "VULNERABLE" "화면보호기 대기시간(10분 이하·작동) 또는 재시작 시 암호 보호 설정이 기준에 부합하지 않으므로 설정 변경 필요."
else
    print_result "PC-16" "MANUAL" "화면보호기 설정 일부를 확인할 수 없음(대기시간=$IDLE_TIME, 암호요구=$ASK_PASS). 시스템 설정에서 대기시간 10분 이하 및 암호 요구 설정 수동 확인 필요."
fi
end_check "16"

# ---------------------------------------------------------------------
# PC-17 CD, DVD, USB 등 이동식 미디어 보안대책 수립
# ---------------------------------------------------------------------
begin_check "17" "PC-17" "CD, DVD, USB 메모리 등과 같은 미디어의 자동실행 방지 등 이동식 미디어에 대한 보안대책 수립"
print_na_macos "PC-17"
end_check "17"

# ---------------------------------------------------------------------
# PC-18 원격 지원 금지 정책 설정
# ---------------------------------------------------------------------
begin_check "18" "PC-18" "원격 지원 금지 정책 설정"
echo "Remote Login, Remote Apple Events, Remote Management, Screen Sharing 비활성화 여부 점검"
echo ""
echo "[현황]"
echo "1. 원격 기능 설정 확인"
REMOTE_LOGIN="$(systemsetup -getremotelogin 2>/dev/null)"
REMOTE_EVENTS="$(systemsetup -getremoteappleevents 2>/dev/null)"
KICKSTART="/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart"
ARD_STATUS=""
[ -x "$KICKSTART" ] && ARD_STATUS="$($KICKSTART -status 2>/dev/null)"
SS_STATUS="$(launchctl print system/com.apple.screensharing 2>/dev/null | head -n 12)"
SS_PROCESS="$(pgrep -f "screensharing|ScreensharingAgent" 2>/dev/null)"
echo "${REMOTE_LOGIN:-Remote Login: 확인 불가}"
echo "${REMOTE_EVENTS:-Remote Apple Events: 확인 불가}"
echo "${ARD_STATUS:-Remote Management: 확인 불가 또는 미사용}"
if [ -n "$SS_PROCESS" ]; then
    echo "Screen Sharing: On 또는 관련 프로세스 실행 중 ($SS_PROCESS)"
elif echo "$SS_STATUS" | grep -Eqi "state[[:space:]]*=[[:space:]]*running"; then
    echo "Screen Sharing: On 또는 서비스 실행 중"
else
    echo "Screen Sharing: Off 또는 실행 중 아님"
fi
REMOTE_LOGIN_ON=0
REMOTE_EVENTS_ON=0
ARD_ON=0
SCREEN_SHARING_ON=0
echo "$REMOTE_LOGIN" | grep -qi "On" && REMOTE_LOGIN_ON=1
echo "$REMOTE_EVENTS" | grep -qi "On" && REMOTE_EVENTS_ON=1
echo "$ARD_STATUS" | grep -Eqi "Remote Management:[[:space:]]*On|Activated|enabled" && ARD_ON=1
{ [ -n "$SS_PROCESS" ] || echo "$SS_STATUS" | grep -Eqi "state[[:space:]]*=[[:space:]]*running"; } && SCREEN_SHARING_ON=1
if [ "$REMOTE_LOGIN_ON" -eq 1 ] || [ "$REMOTE_EVENTS_ON" -eq 1 ] || [ "$ARD_ON" -eq 1 ] || [ "$SCREEN_SHARING_ON" -eq 1 ]; then
    print_result "PC-18" "VULNERABLE" "원격 지원 또는 원격 접속 관련 기능이 활성화되어 있으므로 불필요한 경우 비활성화 필요."
elif echo "$REMOTE_LOGIN" | grep -qi "Off" && echo "$REMOTE_EVENTS" | grep -qi "Off" && [ "$ARD_ON" -eq 0 ] && [ "$SCREEN_SHARING_ON" -eq 0 ]; then
    print_result "PC-18" "GOOD" ""
else
    print_result "PC-18" "MANUAL" "원격 기능 상태를 모두 확인할 수 없음. 시스템 설정 > 일반 > 공유에서 원격 관련 기능 비활성화 여부 확인 필요."
fi
end_check "18"

# ---------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------
echo ""
echo "============================================================"
echo "                 보안 점검 요약 (SUMMARY)"
echo "============================================================"
printf "  1. 양호 (GOOD)       : %d 건\n" "$GOOD_COUNT"
printf "  2. 취약 (VULNERABLE) : %d 건\n" "$VULN_COUNT"
printf "  3. 수동 (MANUAL)     : %d 건\n" "$MANUAL_COUNT"
printf "  4. 해당없음 (N/A)    : %d 건\n" "$NA_COUNT"
echo "------------------------------------------------------------"
printf "전체 점검 항목수     : %d 건\n" "$TOTAL_COUNT"
echo "============================================================"
echo ""
echo "결과 파일: $REPORT_FILE"
