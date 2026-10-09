#!/bin/bash
# =====================================================================
#  run.sh — установщик, сборщик и запускалка Gotcha Linux (C++17 + Qt6)
#
#  Использование:
#     ./run.sh                 # интерактивное меню
#     ./run.sh install         # установить системные зависимости
#     ./run.sh build           # собрать GotchaLinux
#     ./run.sh run             # запустить (найдёт build/GotchaLinux, main, ...)
#     ./run.sh all             # install + build + run
#     ./run.sh check           # проверить окружение
#
#  Ключи:
#     --no-sudo / --clean / --release / --debug
# =====================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR"
BUILD_DIR="$SCRIPT_DIR/build"

# Куда и под какими именами искать готовый бинарник (по порядку приоритета).
BIN_NAMES=(GotchaLinux gotcha Gotcha main)
BIN_SEARCH_DIRS=("$BUILD_DIR" "$SCRIPT_DIR")

ASSUME_NO_SUDO=0
CLEAN_BUILD=0
BUILD_TYPE="Release"
MODE="menu"

for arg in "$@"; do
    case "$arg" in
        --no-sudo) ASSUME_NO_SUDO=1 ;;
        --clean)   CLEAN_BUILD=1 ;;
        --release) BUILD_TYPE="Release" ;;
        --debug)   BUILD_TYPE="RelWithDebInfo" ;;
        install|build|run|all|check) MODE="$arg" ;;
    esac
done

# ---------- цвета ----------
if [ -t 1 ]; then
    C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'
    C_BLU=$'\033[34m'; C_BLD=$'\033[1m';  C_RST=$'\033[0m'
else
    C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_BLD=""; C_RST=""
fi
info() { echo "${C_BLU}[i]${C_RST} $*"; }
ok()   { echo "${C_GRN}[+]${C_RST} $*"; }
warn() { echo "${C_YEL}[!]${C_RST} $*"; }
err()  { echo "${C_RED}[x]${C_RST} $*" >&2; }
hdr()  { echo; echo "${C_BLD}=== $* ===${C_RST}"; }

# ---------- sudo ----------
SUDO=""
init_sudo() {
    if [ "$ASSUME_NO_SUDO" -eq 1 ]; then SUDO=""; return; fi
    if [ "$(id -u)" -eq 0 ]; then SUDO=""
    elif command -v sudo >/dev/null 2>&1; then SUDO="sudo"
    elif command -v doas >/dev/null 2>&1; then SUDO="doas"
    else SUDO=""; warn "sudo/doas не найдены."; fi
}

# ---------- поиск готового бинарника ----------
# Печатает путь к бинарнику (первый найденный), либо пустую строку.
find_bin() {
    local name d
    for d in "${BIN_SEARCH_DIRS[@]}"; do
        [ -d "$d" ] || continue
        for name in "${BIN_NAMES[@]}"; do
            if [ -x "$d/$name" ] && [ ! -d "$d/$name" ]; then
                echo "$d/$name"
                return 0
            fi
        done
    done
    return 1
}

have_binary() { find_bin >/dev/null 2>&1; }

have_sources() {
    [ -f "$SRC_DIR/main.cpp" ] && [ -f "$SRC_DIR/CMakeLists.txt" ]
}

# ---------- дистрибутив ----------
DISTRO=""; DISTRO_NAME=""; PKG_MGR=""; INSTALL_CMD=""
RUNTIME_PKGS=""; BUILD_PKGS=""

detect_distro() {
    if   [ -f /etc/garuda-release ];   then DISTRO=garuda;   DISTRO_NAME="Garuda Linux"
    elif [ -f /etc/manjaro-release ];  then DISTRO=manjaro;  DISTRO_NAME="Manjaro"
    elif [ -f /etc/arch-release ];     then DISTRO=arch;     DISTRO_NAME="Arch Linux"
    elif [ -f /etc/fedora-release ];   then DISTRO=fedora;   DISTRO_NAME="Fedora"
    elif [ -f /etc/altlinux-release ]; then DISTRO=altlinux; DISTRO_NAME="ALT Linux"
    elif [ -f /etc/rocky-release ];    then DISTRO=rocky;    DISTRO_NAME="Rocky Linux"
    elif [ -f /etc/almalinux-release ];then DISTRO=alma;     DISTRO_NAME="AlmaLinux"
    elif [ -f /etc/redhat-release ];   then DISTRO=rhel;     DISTRO_NAME="RHEL/CentOS"
    elif [ -f /etc/opensuse-release ] || [ -f /etc/SuSE-release ]; then
        DISTRO=opensuse; DISTRO_NAME="openSUSE"
    elif [ -f /etc/mageia-release ];   then DISTRO=mageia;   DISTRO_NAME="Mageia"
    elif [ -f /etc/solus-release ];    then DISTRO=solus;    DISTRO_NAME="Solus"
    elif [ -f /etc/void-release ];     then DISTRO=void;     DISTRO_NAME="Void Linux"
    elif [ -f /etc/gentoo-release ];   then DISTRO=gentoo;   DISTRO_NAME="Gentoo"
    elif [ -f /etc/alpine-release ];   then DISTRO=alpine;   DISTRO_NAME="Alpine Linux"
    elif [ -f /etc/debian_version ]; then
        . /etc/os-release 2>/dev/null
        DISTRO=debian
        DISTRO_NAME="${PRETTY_NAME:-Debian/Ubuntu}"
    else
        DISTRO=unknown; DISTRO_NAME="Неизвестный Linux"
    fi

    case "$DISTRO" in
        debian)
            PKG_MGR="apt"; INSTALL_CMD="$SUDO apt-get install -y"
            RUNTIME_PKGS="libqt6widgets6 libqt6network6 libqt6gui6 qt6-qpa-plugins libpcap0.8"
            BUILD_PKGS="build-essential cmake pkg-config qt6-base-dev qt6-base-dev-tools libpcap-dev libgl1-mesa-dev libxkbcommon-dev"
            ;;
        altlinux)
            PKG_MGR="apt"; INSTALL_CMD="$SUDO apt-get install -y"
            RUNTIME_PKGS="libqt6-widgets libqt6-network libqt6-gui qt6-base libpcap"
            BUILD_PKGS="gcc-c++ make cmake pkg-config qt6-base-devel libpcap-devel libGL-devel libxkbcommon-devel"
            ;;
        arch|garuda|manjaro)
            PKG_MGR="pacman"; INSTALL_CMD="$SUDO pacman -S --needed --noconfirm"
            RUNTIME_PKGS="qt6-base libpcap"
            BUILD_PKGS="base-devel cmake pkgconf qt6-base libpcap"
            ;;
        fedora|rhel|rocky|alma)
            PKG_MGR="dnf"; INSTALL_CMD="$SUDO dnf install -y"
            RUNTIME_PKGS="qt6-qtbase qt6-qtbase-gui libpcap"
            BUILD_PKGS="gcc gcc-c++ make cmake pkgconf-pkg-config qt6-qtbase-devel libpcap-devel mesa-libGL-devel libxkbcommon-devel"
            ;;
        opensuse)
            PKG_MGR="zypper"; INSTALL_CMD="$SUDO zypper --non-interactive install"
            RUNTIME_PKGS="libQt6Widgets6 libQt6Network6 libQt6Gui6 libpcap1"
            BUILD_PKGS="gcc gcc-c++ make cmake pkg-config qt6-base-devel libpcap-devel Mesa-libGL-devel libxkbcommon-devel"
            ;;
        mageia)
            PKG_MGR="dnf"; INSTALL_CMD="$SUDO dnf install -y"
            RUNTIME_PKGS="libqt6widgets6 libqt6network6 libqt6gui6 libpcap2"
            BUILD_PKGS="gcc gcc-c++ make cmake pkgconfig qt6-base-devel libpcap-devel libglvnd-devel libxkbcommon-devel"
            ;;
        solus)
            PKG_MGR="eopkg"; INSTALL_CMD="$SUDO eopkg install -y"
            RUNTIME_PKGS="qt6-base libpcap"
            BUILD_PKGS="system.devel cmake pkg-config qt6-base-devel libpcap-devel"
            ;;
        void)
            PKG_MGR="xbps"; INSTALL_CMD="$SUDO xbps-install -y"
            RUNTIME_PKGS="qt6-base libpcap"
            BUILD_PKGS="base-devel cmake pkg-config qt6-base-devel libpcap-devel MesaLib-devel libxkbcommon-devel"
            ;;
        gentoo)
            PKG_MGR="emerge"; INSTALL_CMD="$SUDO emerge --noreplace"
            RUNTIME_PKGS="dev-qt/qtbase net-libs/libpcap"
            BUILD_PKGS="dev-build/cmake sys-devel/gcc dev-util/pkgconf dev-qt/qtbase"
            ;;
        alpine)
            PKG_MGR="apk"; INSTALL_CMD="$SUDO apk add"
            RUNTIME_PKGS="qt6-qtbase libpcap"
            BUILD_PKGS="build-base cmake pkgconf qt6-qtbase-dev libpcap-dev mesa-dev libxkbcommon-dev"
            ;;
        *) PKG_MGR="" ;;
    esac
}

# ---------- проверки ----------
has_cmd() { command -v "$1" >/dev/null 2>&1; }
has_pkgconfig() { has_cmd pkg-config && pkg-config --exists "$1" 2>/dev/null; }
has_libpcap() { has_pkgconfig libpcap; }
has_qt6() {
    if has_cmd cmake; then
        cmake --find-package -DNAME=Qt6 -DCOMPILER_ID=GNU -DLANGUAGE=CXX -DMODE=EXIST \
            >/dev/null 2>&1 && return 0
    fi
    has_pkgconfig Qt6Core || has_pkgconfig Qt6Widgets
}
has_lib() {
    local name="$1" hits
    if has_cmd ldconfig; then
        ldconfig -p 2>/dev/null | grep -q -- "$name" && return 0
    fi
    hits=$(find /usr/lib /usr/lib64 /usr/lib/* /usr/local/lib -maxdepth 2 \
                -name "${name}*" -print -quit 2>/dev/null)
    [ -n "$hits" ]
}

# ---------- проверка окружения ----------
check_all() {
    hdr "Проверка окружения"
    echo "Дистрибутив       : $DISTRO_NAME"
    echo "Пакетный менеджер : ${PKG_MGR:-не определён}"
    echo "Build type        : $BUILD_TYPE"
    echo "Каталог скрипта   : $SRC_DIR"
    echo "Каталог сборки    : $BUILD_DIR"
    echo

    local miss_build=0 miss_runtime=0

    has_cmd cmake     && ok "cmake: $(cmake --version|head -1)"       || { warn "cmake НЕ найден";    miss_build=1; }
    has_cmd g++       && ok "g++: $(g++ --version|head -1)"           || { warn "g++ НЕ найден";      miss_build=1; }
    has_cmd pkg-config&& ok "pkg-config: $(pkg-config --version)"     || { warn "pkg-config НЕ найден"; miss_build=1; }

    if has_libpcap; then
        ok "libpcap (pkg-config): $(pkg-config --modversion libpcap)"
    else
        warn "libpcap НЕ найден"; miss_runtime=1; miss_build=1
    fi

    if has_qt6; then
        ok "Qt6 найден"
    else
        warn "Qt6 НЕ найден (нужен qt6-base-dev)"; miss_runtime=1; miss_build=1
    fi

    has_lib 'libQt6Widgets.so' && ok "libQt6Widgets.so найдена" || { warn "libQt6Widgets.so НЕ найдена"; miss_runtime=1; }
    has_lib 'libpcap.so'       && ok "libpcap.so найдена"       || { warn "libpcap.so НЕ найдена";       miss_runtime=1; }

    if have_sources; then
        ok "Исходники: main.cpp + CMakeLists.txt"
    else
        warn "Исходники отсутствуют в $SRC_DIR (main.cpp / CMakeLists.txt)"
        echo "     Пересборка недоступна — можно только запустить готовый бинарник."
    fi

    local b
    if b=$(find_bin); then
        ok "Готовый бинарник: $b"
        echo "     Размер: $(du -h "$b" | cut -f1)"
    else
        warn "Готовый бинарник не найден. Ожидаемые имена: ${BIN_NAMES[*]}"
        echo "     Ищу в: ${BIN_SEARCH_DIRS[*]}"
    fi

    # Мусор от предыдущих сборок
    local junk_found=0
    if [ -d "$SCRIPT_DIR/venv" ]; then
        warn "Найден каталог venv/ (от Python-версии) — можно удалить."
        junk_found=1
    fi
    if [ -d "$SCRIPT_DIR/CMakeFiles" ] && [ ! -f "$SCRIPT_DIR/CMakeCache.txt" ]; then
        warn "Найден осиротевший CMakeFiles/ без CMakeCache.txt — можно удалить."
        junk_found=1
    fi
    [ "$junk_found" -eq 1 ] && echo "     Удалить: rm -rf venv CMakeFiles"

    echo
    if [ "$miss_build" -eq 0 ] && [ "$miss_runtime" -eq 0 ]; then
        ok "Всё на месте."
    else
        warn "Не хватает зависимостей. Запустите: $0 install"
    fi
    return $(( miss_runtime || miss_build ))
}

# ---------- установка ----------
install_deps() {
    [ -z "$PKG_MGR" ] && { err "Не удалось определить пакетный менеджер."; return 1; }
    init_sudo
    hdr "Установка зависимостей через $PKG_MGR ($DISTRO_NAME)"
    info "Runtime: $RUNTIME_PKGS"
    info "Build  : $BUILD_PKGS"
    echo

    case "$DISTRO" in
        debian|altlinux) $SUDO apt-get update  || warn "apt-get update с ошибкой";;
        arch|garuda|manjaro) $SUDO pacman -Sy --noconfirm || warn "pacman -Sy с ошибкой";;
        alpine) $SUDO apk update || warn "apk update с ошибкой";;
        void)   $SUDO xbps-install -S || warn "xbps -S с ошибкой";;
    esac

    info "Runtime-пакеты..."
    $INSTALL_CMD $RUNTIME_PKGS || warn "Часть runtime-пакетов не установилась"
    info "Build-пакеты..."
    $INSTALL_CMD $BUILD_PKGS   || err  "Не удалось установить build-пакеты"

    check_all || true
}

# ---------- сборка ----------
build_app() {
    if ! have_sources; then
        err "Нет $SRC_DIR/main.cpp или $SRC_DIR/CMakeLists.txt — собрать нечего."
        echo "Возможные причины:"
        echo "  • исходники не распакованы (проверьте *.tar.gz рядом)"
        echo "  • вы работаете в каталоге только с готовым бинарником (main)"
        return 1
    fi
    has_cmd cmake && has_cmd g++ || { err "cmake/g++ не найдены. $0 install"; return 1; }
    has_qt6       || { err "Qt6 не найден. $0 install"; return 1; }
    has_libpcap   || { err "libpcap-dev не найден. $0 install"; return 1; }

    if [ "$CLEAN_BUILD" -eq 1 ]; then
        info "Очищаю $BUILD_DIR и осиротевшие артефакты в $SRC_DIR"
        rm -rf "$BUILD_DIR"
        rm -rf "$SRC_DIR/CMakeFiles" "$SRC_DIR/CMakeCache.txt" "$SRC_DIR/cmake_install.cmake"
    fi

    hdr "Сборка ($BUILD_TYPE)"
    mkdir -p "$BUILD_DIR"
    cmake -S "$SRC_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
        || { err "cmake configure провалился"; return 1; }

    local jobs; jobs=$(nproc 2>/dev/null || echo 2)
    cmake --build "$BUILD_DIR" -j "$jobs" || { err "Сборка провалилась"; return 1; }

    local b
    if b=$(find_bin); then
        ok "Готово: $b"
        echo "     Размер: $(du -h "$b" | cut -f1)"
    else
        err "После сборки бинарник не найден (искал: ${BIN_NAMES[*]})."
        return 1
    fi
}

# ---------- helper-бинарники атак ----------
CPP_BINS=(DHCPstarvation ARPspoof NPtcpT NPudpT NPicmpT NParpT DNSspoof MACflood)
helper_dirs() { echo "$SCRIPT_DIR/bin" "$BUILD_DIR/bin" "$BUILD_DIR" "$SCRIPT_DIR"; }
find_helper() {
    local n="$1" d
    for d in $(helper_dirs); do
        [ -x "$d/$n" ] && { echo "$d/$n"; return 0; }
    done
    return 1
}
check_cpp_bins() {
    hdr "Проверка helper-бинарников"
    local missing=()
    for b in "${CPP_BINS[@]}"; do
        local p
        if p=$(find_helper "$b"); then ok "$b  ($p)"; else warn "$b — не найден"; missing+=("$b"); fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        echo
        warn "Часть helper'ов отсутствует — соответствующие атаки недоступны."
        for d in $(helper_dirs); do echo "  $d"; done
    fi
}

# ---------- запуск ----------
run_app() {
    local bin
    if ! bin=$(find_bin); then
        warn "Бинарник не найден (искал: ${BIN_NAMES[*]})."
        if have_sources; then
            read -r -p "Собрать сейчас? [Y/n] " a
            [[ "$a" =~ ^[Nn]$ ]] && return 1
            build_app || return 1
            bin=$(find_bin) || { err "Не удалось найти бинарник после сборки"; return 1; }
        else
            err "Исходников нет — собрать нельзя."
            echo "Положите main.cpp + CMakeLists.txt рядом с run.sh или распакуйте архив."
            return 1
        fi
    fi

    [ "$(id -u)" -ne 0 ] && info "Запуск без root — программа сама вызовет pkexec/sudo."

    hdr "Запуск Gotcha Linux"
    info "Бинарник: $bin"
    echo
    exec "$bin" "$@"
}

# ---------- меню ----------
show_menu() {
    local b; b=$(find_bin 2>/dev/null || true)
    cat <<EOF
${C_BLD}Gotcha Linux (Qt6) — установщик, сборщик, запуск${C_RST}
Дистрибутив : $DISTRO_NAME
Пакеты      : ${PKG_MGR:-не определён}
Build type  : $BUILD_TYPE
Бинарник    : ${b:-не найден}
Исходники   : $(have_sources && echo да || echo нет)

  1) Проверить окружение
  2) Установить системные зависимости (Qt6 + libpcap + cmake)
  3) Собрать из исходников
  4) Проверить helper-бинарники
  5) Запустить Gotcha Linux
  6) Всё сразу: install + build + check + run
  7) Очистить build/ и пересобрать
  0) Выход
EOF
}

interactive_menu() {
    while true; do
        show_menu
        read -r -p "Выбор: " choice
        case "$choice" in
            1) check_all || true ;;
            2) install_deps ;;
            3) build_app ;;
            4) check_cpp_bins ;;
            5) run_app ;;
            6) install_deps && build_app && check_cpp_bins && run_app ;;
            7) CLEAN_BUILD=1; build_app ;;
            0) exit 0 ;;
            *) warn "Не понял выбор: $choice" ;;
        esac
        echo
        read -r -p "Нажмите Enter, чтобы вернуться в меню..." _
        clear 2>/dev/null || true
    done
}

# ---------- main ----------
detect_distro
init_sudo

case "$MODE" in
    install) install_deps ;;
    build)   build_app ;;
    run)     run_app ;;
    check)   check_all || true ;;
    all)     install_deps && build_app && check_cpp_bins && run_app ;;
    menu|*)  interactive_menu ;;
esac
