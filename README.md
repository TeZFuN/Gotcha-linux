# Gotcha Linux

Форк проекта **[Gotcha](https://github.com/hedromanie/Gotcha)** — инструмента для тестирования сетевой безопасности, портированный на Linux и переписанный с Python/GTK3 на **C++17 + Qt6 + libpcap**.

---

## 🚀 Особенности

- **Нативный Qt6-интерфейс** на C++ — единый бинарник, никаких Python-зависимостей.
- **Все атаки вынесены в отдельные C++ бинарники** на `libpcap` для максимальной производительности (миллионы PPS).
- **Единая сборка в AppImage** — один файл, который запускается на любом Linux без установки Qt6 и libpcap.
- **Автоматический запрос root** через `pkexec`/`sudo` — программа сама повышает права при запуске.
- **Восстановление графического окружения** (`DISPLAY`, `XAUTHORITY`, `WAYLAND_DISPLAY`) при запуске под root — GUI работает без `sudo -E`.

---

## ⚡ Доступные атаки

| Атака | Описание |
|---|---|
| **DHCP Starvation** | Исчерпание пула IP-адресов DHCP-сервера (DORA с уникальными MAC). |
| **ARP Spoofing** | Подмена ARP-таблиц (MITM) с восстановлением после остановки. |
| **DoS (TCP/UDP/ICMP/ARP)** | Высокоинтенсивный флуд выбранным протоколом с поддержкой случайного IP/MAC. |
| **DNS Spoofing** | Подмена DNS-ответов по правилам (домен → IP) с масками и catch-all. |
| **MAC Flood** | Переполнение CAM-таблицы коммутатора. |
| **Intercept** | Перехват, анализ, редактирование и пересылка пакетов через `libpcap`. |

---

## 📋 Требования

### Runtime (для запуска готового AppImage)

Ничего, кроме ядра Linux и X11/Wayland. Всё остальное упаковано внутрь.

> На системах без FUSE2 (Ubuntu 22.04+, Debian 12+): `sudo apt install libfuse2`

### Для сборки из исходников

- **CMake** ≥ 3.16
- **GCC** ≥ 9 или **Clang** ≥ 10
- **Qt6** (модули Widgets, Network, Gui)
- **libpcap** (dev-пакет)
- **pkg-config**

---

## 🛠 Установка зависимостей

### Arch Linux / Manjaro / Garuda

```bash
sudo pacman -S --needed base-devel cmake pkgconf qt6-base libpcap
```

Для сборки AppImage дополнительно:

```bash
sudo pacman -S --needed patchelf qt6-svg
```

### Debian / Ubuntu / Kali

```bash
sudo apt update
sudo apt install -y build-essential cmake pkg-config \
    qt6-base-dev qt6-base-dev-tools libpcap-dev \
    libgl1-mesa-dev libxkbcommon-dev
```

Для сборки AppImage:

```bash
sudo apt install -y patchelf qt6-svg-dev
```

### Fedora / RHEL / Rocky / AlmaLinux

```bash
sudo dnf install -y gcc gcc-c++ make cmake pkgconf-pkg-config \
    qt6-qtbase-devel libpcap-devel mesa-libGL-devel libxkbcommon-devel
```

### ALT Linux

```bash
sudo apt-get install -y gcc-c++ make cmake pkg-config \
    qt6-base-devel libpcap-devel libGL-devel libxkbcommon-devel
```

### openSUSE

```bash
sudo zypper install -y gcc gcc-c++ make cmake pkg-config \
    qt6-base-devel libpcap-devel Mesa-libGL-devel libxkbcommon-devel
```

### Void Linux

```bash
sudo xbps-install -S base-devel cmake pkg-config \
    qt6-base-devel libpcap-devel MesaLib-devel libxkbcommon-devel
```

### Gentoo

```bash
sudo emerge dev-build/cmake sys-devel/gcc dev-util/pkgconf \
    dev-qt/qtbase net-libs/libpcap
```

### Alpine

```bash
sudo apk add build-base cmake pkgconf \
    qt6-qtbase-dev libpcap-dev mesa-dev libxkbcommon-dev
```

---

## 🔨 Сборка

### Быстрая сборка (на машине, где уже есть Qt6)

```bash
git clone https://github.com/TeZFuN/Gotcha-linux.git
cd Gotcha-linux

mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . -j$(nproc)
```

Готовый бинарник: `build/GotchaLinux`.

### Автоматическая сборка + запуск (рекомендуется)

В репозитории есть `run.sh` — интерактивный установщик, сборщик и launcher:

```bash
chmod +x run.sh
./run.sh
```

Меню:

```
  1) Проверить окружение
  2) Установить системные зависимости
  3) Собрать GotchaLinux из исходников
  4) Проверить C++ helper-бинарники
  5) Запустить Gotcha Linux
  6) Всё сразу: install + build + check + run
  7) Очистить build/ и пересобрать
  0) Выход
```

Режимы командной строки:

```bash
./run.sh install    # только установить зависимости
./run.sh build      # только собрать
./run.sh run        # только запустить
./run.sh all        # install + build + run
./run.sh check      # проверить окружение
./run.sh --clean build    # чистая пересборка
./run.sh --debug build    # сборка с отладочными символами
```

### Сборка AppImage (для распространения на флешке)

Скрипт `build-appimage.sh` собирает самодостаточный `.AppImage`, включающий Qt6, libpcap и все helper-бинарники.

**Что нужно положить рядом со скриптом:**

```
gotcha-build/
├── build-appimage.sh
├── main                  ← скомпилированный главный бинарник
├── bin/                  ← helper-бинарники атак
│   ├── DHCPstarvation
│   ├── ARPspoof
│   ├── NPtcpT
│   ├── NPudpT
│   ├── NPicmpT
│   ├── NParpT
│   ├── DNSspoof
│   ├── intercept
│   └── MACflood
└── gotcha.png            ← (опц.) иконка 256×256
```

**Запуск:**

```bash
chmod +x build-appimage.sh
./build-appimage.sh --clean
```

Скрипт:

1. Скачает `linuxdeploy` и `linuxdeploy-plugin-qt` в `tools/`.
2. Соберёт `AppDir/` с `qt.conf`, `AppRun`-wrapper'ом, `.desktop` и иконкой.
3. Запустит linuxdeploy с плагином Qt — подтянет Qt6, libpcap, xcb-плагины.
4. Упакует всё в `Gotcha-x86_64.AppImage`.
5. **Уберёт за собой** `AppDir/`, `.qt-plugins-curated/`, `.qmake6-wrapper`, `squashfs-root/`.

**Флаги:**

```bash
./build-appimage.sh --clean            # пересобрать с нуля
./build-appimage.sh --skip-appstream   # не генерить appdata.xml (если AppStream-валидация падает)
./build-appimage.sh --keep-work        # не удалять AppDir после сборки (для отладки)
./build-appimage.sh --no-download      # не скачивать linuxdeploy заново
```

Готовый AppImage — **~60–90 МиБ**, запускается на любой системе с X11/Wayland.

---

## ▶️ Запуск

### Прямой запуск бинарника

```bash
# Программа сама запросит root через pkexec/sudo
./build/GotchaLinux

# Или явно от root
sudo -E ./build/GotchaLinux
```

### Запуск AppImage

```bash
chmod +x Gotcha-x86_64.AppImage

# Двойной клик в файловом менеджере ИЛИ:
./Gotcha-x86_64.AppImage

# Если система без FUSE2:
./Gotcha-x86_64.AppImage --appimage-extract-and-run
```

При запуске без root программа автоматически перезапустится через `pkexec` (GUI-friendly) или `sudo -E` (fallback).

---

## 📁 Структура проекта

```
Gotcha-linux/
├── main.cpp                 # весь Qt6-интерфейс (однофайловый порт)
├── CMakeLists.txt           # сборка Qt6 + libpcap
├── run.sh                   # универсальный installer/builder/launcher
├── build-appimage.sh        # сборка AppImage
├── README.md
└── bin/                     # helper-бинарники атак (C++ + libpcap)
    ├── DHCPstarvation
    ├── ARPspoof
    ├── NPtcpT
    ├── NPudpT
    ├── NPicmpT
    ├── NParpT
    ├── DNSspoof
    ├── intercept
    └── MACflood
```

---

## ⚠️ Предупреждение

Данный инструмент предназначен **исключительно** для тестирования собственных сетей или сетей, на которые у вас есть **письменное разрешение**. Любое несанкционированное использование является **противозаконным** и влечёт уголовную ответственность. Автор не несёт ответственности за неправомерное использование.

---

## 🐛 Известные проблемы

- **`QList::operator[]: index out of range` при выходе** — известный баг QPA-плагина Qt 6.12. Обходится через `std::_Exit(rc)` после `app.exec()` в `main.cpp`. Будет исправлено при обновлении Qt.
- **`env: … Отказано в доступе` при запуске AppImage без sudo** — FUSE-mount user-private, `pkexec` не видит `/tmp/.mount_XXXX/`. Исправляется через `$APPIMAGE` в `relaunchAsRoot()`: перезапускать сам `.AppImage`, а не внутренний бинарник.

---

## 📚 Ссылки

- Оригинальный проект: [hedromanie/Gotcha](https://github.com/hedromanie/Gotcha)
- Данный форк: [TeZFuN/Gotcha-linux](https://github.com/TeZFuN/Gotcha-linux)

---

## 📄 Лицензия

Проект распространяется под лицензией **MIT**.
