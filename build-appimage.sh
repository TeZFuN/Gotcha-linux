#!/bin/bash
# =====================================================================
#  build-appimage.sh — собирает Gotcha Linux в один .AppImage
#  v5: корректный AppRun-wrapper + автоуборка после сборки
#
#  Использование:
#     ./build-appimage.sh                    # собрать и убрать за собой
#     ./build-appimage.sh --clean            # начать с нуля
#     ./build-appimage.sh --no-download      # не качать linuxdeploy
#     ./build-appimage.sh --skip-appstream   # не генерить appdata.xml
#     ./build-appimage.sh --keep-work        # НЕ удалять AppDir/tools после сборки
#
#  Что нужно рядом со скриптом:
#     main (или GotchaLinux/gotcha/Gotcha)  — главный бинарник
#     bin/                                   — helper-бинарники атак
#     gotcha.png                             — (опц.) иконка 256x256
#
#  После успешной сборки:
#     • в каталоге остаётся Gotcha-x86_64.AppImage
#     • временные AppDir/, .qt-plugins-curated/, .qmake6-wrapper удаляются
#     • tools/ (linuxdeploy) сохраняется — не качать при следующем запуске
# =====================================================================

set -euo pipefail

# ---------- настройки ----------
APP_NAME="Gotcha"
APP_ID="gotcha-linux"
APPSTREAM_ID="com.github.tezfun.gotcha"
APP_VERSION="1.0.0"
APP_HOMEPAGE="https://github.com/TeZFuN/Gotcha-linux"
APP_BUGTRACKER="${APP_HOMEPAGE}/issues"
APP_DEVELOPER_ID="com.github.tezfun"
APP_DEVELOPER_NAME="TeZFuN"

MAIN_BIN_CANDIDATES=("GotchaLinux" "main" "gotcha" "Gotcha")
HELPER_DIR="bin"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$SCRIPT_DIR/tools"
APPDIR="$SCRIPT_DIR/AppDir"
OUTPUT_APPIMAGE="$SCRIPT_DIR/${APP_NAME}-x86_64.AppImage"
ICON_SRC="$SCRIPT_DIR/gotcha.png"
CURATED_PLUGINS="$SCRIPT_DIR/.qt-plugins-curated"
QMAKE_WRAPPER="$SCRIPT_DIR/.qmake6-wrapper"
SQUASHFS_TMP="$SCRIPT_DIR/squashfs-root"

# ---------- парсинг аргументов ----------
CLEAN=0
NO_DOWNLOAD=0
SKIP_APPSTREAM=0
KEEP_WORK=0

for a in "$@"; do
    case "$a" in
        --clean)           CLEAN=1 ;;
        --no-download)     NO_DOWNLOAD=1 ;;
        --skip-appstream)  SKIP_APPSTREAM=1 ;;
        --keep-work)       KEEP_WORK=1 ;;
        -h|--help)
            sed -n 's/^# \{0,1\}//p' "$0" | sed -n '1,40p'
            exit 0
            ;;
        *) echo "Неизвестный аргумент: $a" >&2; exit 2 ;;
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
die()  { err "$*"; exit 1; }
hdr()  { echo; echo "${C_BLD}=== $* ===${C_RST}"; }

# =====================================================================
#  Автоуборка (trap) — срабатывает при любом выходе
# =====================================================================
BUILD_OK=0

cleanup_workdirs() {
    # Всегда чистим squashfs-root (наследие --appimage-extract).
    [ -d "$SQUASHFS_TMP" ] && rm -rf "$SQUASHFS_TMP"

    if [ "$KEEP_WORK" -eq 1 ]; then
        info "--keep-work: рабочие каталоги сохранены (AppDir, .qt-plugins-curated, .qmake6-wrapper)"
        return 0
    fi

    # AppDir нужен только на время сборки — удаляем.
    [ -d "$APPDIR" ]             && rm -rf "$APPDIR"
    [ -d "$CURATED_PLUGINS" ]    && rm -rf "$CURATED_PLUGINS"
    [ -f "$QMAKE_WRAPPER" ]      && rm -f  "$QMAKE_WRAPPER"

    # Осиротевшие *.AppImage, кроме финального.
    local stray
    while IFS= read -r stray; do
        [ -n "$stray" ] || continue
        if [ "$stray" != "$OUTPUT_APPIMAGE" ]; then
            rm -f "$stray"
        fi
    done < <(find "$SCRIPT_DIR" -maxdepth 1 -name 'Gotcha*.AppImage' -type f 2>/dev/null || true)
}
trap cleanup_workdirs EXIT

# =====================================================================
#  Утилиты
# =====================================================================
find_main_bin() {
    local n
    for n in "${MAIN_BIN_CANDIDATES[@]}"; do
        if [ -x "$SCRIPT_DIR/$n" ] && [ ! -d "$SCRIPT_DIR/$n" ]; then
            echo "$SCRIPT_DIR/$n"; return 0
        fi
    done
    return 1
}

find_qmake_qt6() {
    local c
    local candidates=(
        "$(command -v qmake6 2>/dev/null || true)"
        "$(command -v qmake-qt6 2>/dev/null || true)"
        /usr/lib/qt6/bin/qmake
        /usr/lib64/qt6/bin/qmake
        /usr/lib/x86_64-linux-gnu/qt6/bin/qmake
        /usr/lib/aarch64-linux-gnu/qt6/bin/qmake
        /usr/local/lib/qt6/bin/qmake
        /opt/qt6/bin/qmake
    )
    for c in "${candidates[@]}"; do
        if [ -n "$c" ] && [ -x "$c" ]; then
            local ver
            ver=$("$c" -query QT_VERSION 2>/dev/null || true)
            case "$ver" in 6.*) echo "$c"; return 0 ;; esac
        fi
    done
    return 1
}

download_tool() {
    local url="$1" dst="$2"
    if [ -x "$dst" ]; then info "Уже есть: $(basename "$dst")"; return 0; fi
    info "Скачиваю $(basename "$dst")..."
    curl -fL --progress-bar "$url" -o "$dst" || die "Не удалось скачать $url"
    chmod +x "$dst"
}

# =====================================================================
#  Проверка входных данных
# =====================================================================
hdr "Проверка входных данных"

MAIN_BIN="$(find_main_bin)" || die "Не найден главный бинарник. Положи GotchaLinux (или main) рядом со скриптом."
info "Главный бинарник : $MAIN_BIN"
info "Размер           : $(du -h "$MAIN_BIN" | cut -f1)"

if ldd "$MAIN_BIN" 2>/dev/null | grep -q 'libQt6'; then
    ok "ldd подтверждает линковку с Qt6."
elif ldd "$MAIN_BIN" 2>/dev/null | grep -q 'libQt5'; then
    die "Бинарник слинкован с Qt5, а не Qt6. Пересобери под Qt6."
else
    warn "ldd не видит libQt6 — возможно, бинарник статический."
fi

QMAKE_QT6="$(find_qmake_qt6 || true)"
[ -n "$QMAKE_QT6" ] || die "Qt6 qmake не найден. Установи: sudo pacman -S qt6-base"
QT6_VER=$("$QMAKE_QT6" -query QT_VERSION)
QT6_PLUGINS_SRC=$("$QMAKE_QT6" -query QT_INSTALL_PLUGINS)
ok "Qt6 qmake: $QMAKE_QT6 (Qt $QT6_VER)"
info "Qt6 plugins source: $QT6_PLUGINS_SRC"

for c in curl wget file patchelf; do
    command -v "$c" >/dev/null 2>&1 || warn "Не найдена утилита '$c' (нужна linuxdeploy)."
done

# =====================================================================
#  Скачивание linuxdeploy
# =====================================================================
mkdir -p "$TOOLS_DIR"
LD="$TOOLS_DIR/linuxdeploy-x86_64.AppImage"
LD_QT="$TOOLS_DIR/linuxdeploy-plugin-qt-x86_64.AppImage"

if [ "$NO_DOWNLOAD" -eq 0 ]; then
    hdr "Скачивание linuxdeploy"
    download_tool \
        "https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage" \
        "$LD"
    download_tool \
        "https://github.com/linuxdeploy/linuxdeploy-plugin-qt/releases/download/continuous/linuxdeploy-plugin-qt-x86_64.AppImage" \
        "$LD_QT"
else
    [ -x "$LD" ] || die "Нет $LD (--no-download, но файла нет)"
fi

# =====================================================================
#  Очистка от прошлых запусков
# =====================================================================
if [ -d "$APPDIR" ]; then
    info "Удаляю старый AppDir"
    rm -rf "$APPDIR"
fi
if [ "$CLEAN" -eq 1 ]; then
    rm -f "$OUTPUT_APPIMAGE"
    ok "Очищено."
fi

# =====================================================================
#  Урезанный набор Qt-плагинов (только platforms)
# =====================================================================
hdr "Подготовка урезанного набора Qt-плагинов"

rm -rf "$CURATED_PLUGINS"
mkdir -p "$CURATED_PLUGINS/platforms"

for p in libqxcb.so libqwayland.so libqwayland-egl.so libqwayland-generic.so; do
    if [ -f "$QT6_PLUGINS_SRC/platforms/$p" ]; then
        ln -sf "$QT6_PLUGINS_SRC/platforms/$p" "$CURATED_PLUGINS/platforms/$p"
        info "  + platforms/$p"
    fi
done

# Wrapper-qmake: подменяет QT_INSTALL_PLUGINS на урезанную папку.
cat > "$QMAKE_WRAPPER" <<EOF
#!/bin/bash
REAL_QMAKE="$QMAKE_QT6"
FAKE_PLUGINS="$CURATED_PLUGINS"

if [ "\$1" = "-query" ]; then
    if [ \$# -eq 1 ]; then
        "\$REAL_QMAKE" -query | sed "s|^QT_INSTALL_PLUGINS:.*|QT_INSTALL_PLUGINS:\$FAKE_PLUGINS|"
        exit 0
    fi
    if [ "\$2" = "QT_INSTALL_PLUGINS" ]; then
        echo "\$FAKE_PLUGINS"
        exit 0
    fi
fi
exec "\$REAL_QMAKE" "\$@"
EOF
chmod +x "$QMAKE_WRAPPER"
ok "Wrapper qmake: $QMAKE_WRAPPER"

WRAPPER_ANSWER=$("$QMAKE_WRAPPER" -query QT_INSTALL_PLUGINS)
[ "$WRAPPER_ANSWER" = "$CURATED_PLUGINS" ] || die "Wrapper qmake не работает как ожидалось (получено: $WRAPPER_ANSWER)"

# =====================================================================
#  Сборка AppDir
# =====================================================================
hdr "Сборка AppDir"

mkdir -p "$APPDIR/usr/bin"
mkdir -p "$APPDIR/usr/share/applications"
mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"
if [ "$SKIP_APPSTREAM" -eq 0 ]; then
    mkdir -p "$APPDIR/usr/share/metainfo"
fi

# Главный бинарник
cp "$MAIN_BIN" "$APPDIR/usr/bin/$APP_NAME"
chmod +x "$APPDIR/usr/bin/$APP_NAME"

# Helper-бинарники
if [ -d "$SCRIPT_DIR/$HELPER_DIR" ]; then
    for h in "$SCRIPT_DIR/$HELPER_DIR"/*; do
        [ -f "$h" ] || continue
        base=$(basename "$h")
        cp "$h" "$APPDIR/usr/bin/$base"
        chmod +x "$APPDIR/usr/bin/$base"
    done
fi

# Иконка
ICON_DST="$APPDIR/usr/share/icons/hicolor/256x256/apps/$APP_ID.png"
if [ -f "$ICON_SRC" ]; then
    cp "$ICON_SRC" "$ICON_DST"
else
    warn "Иконка '$ICON_SRC' не найдена — генерирую заглушку."
    if command -v magick >/dev/null 2>&1; then
        magick -size 256x256 xc:'#1e40af' -fill white -gravity center \
               -pointsize 96 -annotate 0 'G' "$ICON_DST"
    elif command -v convert >/dev/null 2>&1; then
        convert -size 256x256 xc:'#1e40af' -fill white -gravity center \
                -pointsize 96 -annotate 0 'G' "$ICON_DST"
    else
        python3 - <<'PY' "$ICON_DST"
import sys, struct, zlib
w = h = 256
raw = b''.join(b'\x00' + b'\x1e\x40\xaf' * w for _ in range(h))
def chunk(t, d):
    return struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d) & 0xffffffff)
png = b'\x89PNG\r\n\x1a\n'
png += chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0))
png += chunk(b'IDAT', zlib.compress(raw, 9))
png += chunk(b'IEND', b'')
open(sys.argv[1], 'wb').write(png)
PY
    fi
fi
cp "$ICON_DST" "$APPDIR/$APP_ID.png"

# .desktop
cat > "$APPDIR/usr/share/applications/$APP_ID.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Gotcha Linux
GenericName=Network Security Toolkit
Comment=Network security testing toolkit
Exec=$APP_NAME
Icon=$APP_ID
Terminal=false
Categories=Network;Security;System;
Keywords=network;security;packet;sniff;arp;dns;dhcp;
StartupNotify=true
EOF
cp "$APPDIR/usr/share/applications/$APP_ID.desktop" "$APPDIR/$APP_ID.desktop"

# appdata.xml
if [ "$SKIP_APPSTREAM" -eq 0 ]; then
    cat > "$APPDIR/usr/share/metainfo/$APP_ID.appdata.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop-application">
  <id>${APPSTREAM_ID}</id>
  <name>Gotcha Linux</name>
  <summary>Network security testing toolkit</summary>
  <metadata_license>MIT</metadata_license>
  <project_license>MIT</project_license>

  <description>
    <p>
      Gotcha Linux is a GUI toolkit for auditing and testing network security.
      It provides packet capture and editing, DHCP starvation, ARP spoofing,
      DoS traffic generation, DNS spoofing, and MAC flooding, all driven from
      a single Qt6 interface. Active attacks require root privileges and are
      intended for authorized security testing only.
    </p>
  </description>

  <url type="homepage">${APP_HOMEPAGE}</url>
  <url type="bugtracker">${APP_BUGTRACKER}</url>

  <launchable type="desktop-id">${APP_ID}.desktop</launchable>

  <developer id="${APP_DEVELOPER_ID}">
    <name>${APP_DEVELOPER_NAME}</name>
  </developer>

  <content_rating type="oars-1.1"/>

  <categories>
    <category>Network</category>
    <category>Security</category>
    <category>System</category>
  </categories>

  <releases>
    <release version="${APP_VERSION}" date="$(date +%Y-%m-%d)">
      <description><p>AppImage release.</p></description>
    </release>
  </releases>
</component>
EOF
    ok "appdata.xml создан: $APPSTREAM_ID"
else
    warn "--skip-appstream: appdata.xml не создаётся."
fi

# ---------------------------------------------------------------
#  qt.conf — сообщает Qt, где искать плагины (обязательно!)
# ---------------------------------------------------------------
cat > "$APPDIR/usr/bin/qt.conf" <<'EOF'
[Paths]
Prefix = ..
Plugins = plugins
Imports = qml
Qml2Imports = qml
EOF
ok "qt.conf создан"

# ---------------------------------------------------------------
#  AppRun — bash-wrapper (НЕ симлинк). Выставляет пути до старта Qt.
#  linuxdeploy не перезапишет существующий AppRun.
# ---------------------------------------------------------------
cat > "$APPDIR/AppRun" <<'APPRUN_EOF'
#!/bin/bash
# AppRun для Gotcha Linux AppImage.
# Выставляет переменные, которые Qt читает ДО инициализации QApplication.
# Без этого под FUSE-mount'ом AppImage Qt не находит плагины.

SELF="$(readlink -f "$0")"
APPDIR="$(dirname "$SELF")"

export APPDIR
export LD_LIBRARY_PATH="$APPDIR/usr/lib:${LD_LIBRARY_PATH:-}"
export QT_PLUGIN_PATH="$APPDIR/usr/plugins"
export QT_QPA_PLATFORM_PLUGIN_PATH="$APPDIR/usr/plugins/platforms"
export QML2_IMPORT_PATH="$APPDIR/usr/qml"

# xcb по умолчанию (Wayland-плагин не упаковываем намеренно).
if [ -z "${QT_QPA_PLATFORM:-}" ]; then
    export QT_QPA_PLATFORM=xcb
fi

exec "$APPDIR/usr/bin/Gotcha" "$@"
APPRUN_EOF
chmod +x "$APPDIR/AppRun"
ok "AppRun-wrapper создан (не симлинк)"

ok "AppDir собран: $APPDIR"

# =====================================================================
#  Запуск linuxdeploy
# =====================================================================
hdr "Запуск linuxdeploy"

# Не стрипать — иначе падает на .relr.dyn (новые ELF-секции).
export NO_STRIP=1

# Чистим окружение от чужих Qt-путей.
unset LD_LIBRARY_PATH
unset QT_PLUGIN_PATH
unset QML2_IMPORT_PATH
unset EXTRA_QT_MODULES
unset EXTRA_QT_PLUGINS
unset EXTRA_PLATFORM_PLUGINS

# Wrapper-qmake — критично для Qt6 и урезанного набора плагинов.
export QMAKE="$QMAKE_WRAPPER"
info "QMAKE=$QMAKE"

export PATH="$TOOLS_DIR:$PATH"

cd "$SCRIPT_DIR"

set +e
"$LD" \
    --appdir "$APPDIR" \
    --plugin qt \
    --desktop-file "$APPDIR/usr/share/applications/$APP_ID.desktop" \
    --icon-file   "$APPDIR/usr/share/icons/hicolor/256x256/apps/$APP_ID.png" \
    --executable  "$APPDIR/usr/bin/$APP_NAME" \
    --output appimage
LD_RC=$?
set -e

if [ $LD_RC -ne 0 ]; then
    err "linuxdeploy завершился с кодом $LD_RC"
    echo
    echo "Подсказки:"
    echo "  • ошибка AppStream — перезапусти с --skip-appstream"
    echo "  • 'Could not find dependency' — доустанови пакет или расширь Qt-плагины"
    echo "  • диагностику сохрани через --keep-work"
    exit $LD_RC
fi

# =====================================================================
#  Проверка: AppRun остался нашим скриптом?
# =====================================================================
if [ -L "$APPDIR/AppRun" ]; then
    warn "linuxdeploy заменил AppRun симлинком — восстанавливаю wrapper"
    rm -f "$APPDIR/AppRun"
    # Восстанавливаем из бэкапа, если он есть; иначе — генерируем заново
    cat > "$APPDIR/AppRun" <<'APPRUN_EOF'
#!/bin/bash
SELF="$(readlink -f "$0")"
APPDIR="$(dirname "$SELF")"
export APPDIR
export LD_LIBRARY_PATH="$APPDIR/usr/lib:${LD_LIBRARY_PATH:-}"
export QT_PLUGIN_PATH="$APPDIR/usr/plugins"
export QT_QPA_PLATFORM_PLUGIN_PATH="$APPDIR/usr/plugins/platforms"
export QML2_IMPORT_PATH="$APPDIR/usr/qml"
if [ -z "${QT_QPA_PLATFORM:-}" ]; then
    export QT_QPA_PLATFORM=xcb
fi
exec "$APPDIR/usr/bin/Gotcha" "$@"
APPRUN_EOF
    chmod +x "$APPDIR/AppRun"
fi

# =====================================================================
#  Перенос результата
# =====================================================================
GENERATED=$(ls -1 "$SCRIPT_DIR"/${APP_NAME}-*.AppImage 2>/dev/null | head -1 || true)
if [ -z "$GENERATED" ]; then
    GENERATED=$(find "$SCRIPT_DIR" -maxdepth 1 -name '*.AppImage' \
                    -not -name 'linuxdeploy*' -print -quit 2>/dev/null || true)
fi

if [ -n "$GENERATED" ] && [ -f "$GENERATED" ]; then
    mv -f "$GENERATED" "$OUTPUT_APPIMAGE"
    chmod +x "$OUTPUT_APPIMAGE"
    ok "Готово: $OUTPUT_APPIMAGE"
    echo "     Размер: $(du -h "$OUTPUT_APPIMAGE" | cut -f1)"
else
    err "linuxdeploy не создал .AppImage"
    exit 1
fi

# =====================================================================
#  Финальная проверка
# =====================================================================
hdr "Проверка"

if "$OUTPUT_APPIMAGE" --appimage-extract >/dev/null 2>&1; then
    if find "$SQUASHFS_TMP" -name 'libQt6Core.so*' -print -quit | grep -q .; then
        ok "libQt6Core.so упакован."
    else
        warn "libQt6Core.so НЕ найден!"
    fi
    if find "$SQUASHFS_TMP" -name 'libqxcb.so' -print -quit | grep -q .; then
        ok "libqxcb.so (платформенный плагин) упакован."
    else
        warn "libqxcb.so НЕ найден — GUI не запустится!"
    fi
    if find "$SQUASHFS_TMP" -name 'libQt5Core.so*' -print -quit | grep -q .; then
        warn "Обнаружен libQt5Core.so — что-то тянет Qt5!"
    fi
    if find "$SQUASHFS_TMP" -name 'libpcap.so*' -print -quit | grep -q .; then
        ok "libpcap.so упакован."
    else
        warn "libpcap.so НЕ найден!"
    fi
    if [ -f "$SQUASHFS_TMP/usr/bin/qt.conf" ]; then
        ok "qt.conf упакован."
    else
        warn "qt.conf НЕ найден!"
    fi
    if [ -x "$SQUASHFS_TMP/AppRun" ] && [ ! -L "$SQUASHFS_TMP/AppRun" ]; then
        ok "AppRun — исполняемый скрипт (не симлинк)."
    elif [ -L "$SQUASHFS_TMP/AppRun" ]; then
        warn "AppRun — симлинк, Qt может не найти плагины."
    fi

    LIBS_COUNT=$(find "$SQUASHFS_TMP/usr/lib" -maxdepth 1 -name '*.so*' 2>/dev/null | wc -l)
    PLUGINS_COUNT=$(find "$SQUASHFS_TMP/usr/plugins" -type f -name '*.so' 2>/dev/null | wc -l)
    BINS_COUNT=$(find "$SQUASHFS_TMP/usr/bin" -maxdepth 1 -type f 2>/dev/null | wc -l)
    info "Библиотек в AppImage : $LIBS_COUNT"
    info "Плагинов Qt         : $PLUGINS_COUNT"
    info "Бинарников в usr/bin: $BINS_COUNT"
    rm -rf "$SQUASHFS_TMP"
fi

if "$OUTPUT_APPIMAGE" --appimage-version >/dev/null 2>&1; then
    ok "AppImage корректно отвечает на --appimage-version"
fi

BUILD_OK=1

echo
echo "${C_BLD}Запуск:${C_RST}    $OUTPUT_APPIMAGE"
echo "${C_BLD}Root:${C_RST}      sudo -E $OUTPUT_APPIMAGE"
echo "${C_BLD}Без FUSE2:${C_RST} $OUTPUT_APPIMAGE --appimage-extract-and-run"
echo
ok "Сборка завершена."

# EXIT-trap удалит AppDir/.qt-plugins-curated/.qmake6-wrapper,
# если не был указан --keep-work.
