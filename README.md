# Gotcha Linux

Форк оригинального проекта **[Gotcha](https://github.com/hedromanie/Gotcha)** – инструмента для тестирования сетевой безопасности, адаптированный для работы в среде **Linux** (Fedora, Ubuntu, Arch и др.).

---

## 🚀 Особенности

- Полнофункциональный **GTK-интерфейс** на Python (заменяет Windows-версию).
- Все атаки вынесены в **нативные C++ бинарники** для максимальной производительности (используют `libpcap`).
- **Высокая скорость** отправки пакетов (достигает миллионов PPS) благодаря многопоточности и прямому доступу к сетевому интерфейсу.
- **Портабельность**: проект собран в виде архива с исходниками и может быть развёрнут на любой Linux-системе.

---

## ⚡ Доступные атаки

| Атака | Описание |
|-------|----------|
| **DHCP Starvation** | Исчерпание пула IP-адресов DHCP-сервера (атака DORA с уникальными MAC). |
| **ARP Spoofing** | Подмена ARP-таблиц (MITM) с восстановлением после остановки. |
| **DoS (TCP/UDP/ICMP/ARP)** | Высокоинтенсивный флуд выбранным протоколом с поддержкой случайного IP/MAC. |
| **DNS Spoofing** | Подмена DNS-ответов по правилам (домен → IP) с масками и catch-all. |
| **MAC flood** | Переполнение CAM-таблицы коммутатора. |
| **Intercept** | Перехват, анализ, редактирование и пересылка пакетов (с автоматическими ответами ICMP). |

---

## 🛠️ Требования

- **Linux** (любой дистрибутив, поддерживающий `libpcap`).
- **Python 3.14+** (или 3.12/3.13) с модулями: `scapy`, `netifaces`, `psutil`, `PyGObject` (GTK3).
- **libpcap-dev** (для компиляции бинарников).
- **Права root** (большинство атак требуют доступа к сетевому интерфейсу).

---

## 📦 Установка

### 1. Склонируйте репозиторий

```bash
git clone https://github.com/TeZFuN/Gotcha-linux.git
cd Gotcha-linux
```

### 2. Установите зависимости

🐧 Linux

Arch Linux / Manjaro
```
sudo pacman -S libpcap qt5-base base-devel python-gobject gtk3 arp-scan
pip3 install scapy netifaces
```
Debian / Ubuntu / Kali
```
sudo apt update
sudo apt install libpcap-dev qtbase5-dev build-essential python3-gi gir1.2-gtk-3.0 arp-scan
pip3 install scapy netifaces
```
Fedora / RHEL
```
sudo dnf install libpcap-devel qt5-qtbase-devel gcc-c++ make python3-gobject gtk3-devel arp-scan
pip3 install scapy netifaces
```
ALT Linux
```
sudo apt-get install libpcap-devel qt5-qtbase-devel gcc-c++ make python3-module-gi gtk+3.0 arp-scan
pip3 install scapy netifaces
```
 Gentoo
```
sudo emerge net-libs/libpcap dev-qt/qtgui:5 sys-devel/gcc sys-devel/make dev-python/pygobject x11-libs/gtk+:3 net-analyzer/arp-scan
pip3 install scapy netifaces
```
Void Linux
```
sudo xbps-install -S libpcap-devel qt5-devel base-devel python3-PyGObject gtk+3-devel arp-scan
pip3 install scapy netifaces
```
<br>
### 3. Запустите GUI

```bash
sudo python3 newgui.py
```
PS: Советую установить Wireshark для мониторинга пакетов которые генерирует программа.

## ⚠️ Предупреждение

Данный инструмент предназначен **исключительно** для тестирования собственных сетей или сетей, на которые у вас есть письменное разрешение. Любое несанкционированное использование является **противозаконным** и влечёт уголовную ответственность. Автор не несёт ответственности за неправомерное использование.

---

## 🔗 Ссылки

- Оригинальный проект: [hedromanie/Gotcha](https://github.com/hedromanie/Gotcha)
- Данный форк: [TeZFuN/Gotcha-linux](https://github.com/TeZFuN/Gotcha-linux)

---

## 📄 Лицензия

Проект распространяется под лицензией **MIT** 

---

Известные ошибки:
Не корректная работа таймера 
Не рабочая статистика

---

Вопрос/Ответ

В: Когда 1.0 ?<br>
О: Когда все отестирую и буду уверен что программа будет работать на любой конфигурации ПК и на любом линукс дистрибутиве и в ней не будет багов.<br>

В: Будет ли как-то еще расширяться функционал программы или улучшаться ее производительность ?<br>
О: В планах есть только работа над оптимизацией и пересмотр некторых решений которые были использованы на первое время.<br>


