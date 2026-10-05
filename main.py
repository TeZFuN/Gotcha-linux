#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gotcha Linux — GUI для тестирования сетевой безопасности.

При запуске без root программа автоматически перезапускается с правами
администратора через pkexec (GUI-friendly) или sudo -E (fallback).
"""
import os
import sys
import shutil

# ========== ПЕРЕЗАПУСК С ПРАВАМИ ROOT ==========
def _relaunch_as_root():
    """Если мы не root — перезапускаем себя через pkexec/sudo.
    Возвращает True, если мы уже root (перезапуск не нужен).
    В случае успешного exec управление в вызывающий код не возвращается.
    """
    if os.geteuid() == 0:
        return True

    script = os.path.abspath(sys.argv[0])
    if not os.path.isfile(script):
        print(f"[!] Не найден скрипт для перезапуска: {script}", file=sys.stderr)
        return False

    python = sys.executable or "python3"

    # Переменные окружения, которые нужно сохранить, чтобы GUI запустился
    keep_keys = (
        "DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY",
        "XDG_RUNTIME_DIR", "XDG_SESSION_TYPE",
        "DBUS_SESSION_BUS_ADDRESS",
    )
    keep = {k: os.environ[k] for k in keep_keys if os.environ.get(k)}
    env_args = [f"{k}={v}" for k, v in keep.items()]

    argv_rest = [python, script] + sys.argv[1:]

    print("[i] Требуются права администратора. Запрашиваю...")

    # 1) pkexec — правильный способ для GUI: показывает системный диалог,
    #    не требует терминала, сам сбрасывает привилегии по завершении.
    if shutil.which("pkexec"):
        try:
            os.execvp("pkexec", ["pkexec", "env", *env_args, *argv_rest])
        except OSError as e:
            print(f"[!] pkexec не сработал: {e}", file=sys.stderr)

    # 2) sudo -E — резервный вариант, если pkexec недоступен.
    if shutil.which("sudo"):
        try:
            os.execvp("sudo", ["sudo", "-E", *argv_rest])
        except OSError as e:
            print(f"[!] sudo не сработал: {e}", file=sys.stderr)

    # 3) Ничего не нашли
    print(
        "[x] Не найдены pkexec или sudo.\n"
        "    Запустите программу от root вручную:\n"
        f"        sudo {python} {script}",
        file=sys.stderr,
    )
    sys.exit(1)


# Если мы не root — перезапускаемся и уходим из этого процесса.
_relaunch_as_root()   # после успешного exec сюда управление не вернётся

# ========== ЗДЕСЬ МЫ УЖЕ ROOT ==========
import pwd
import subprocess
import threading
import time
import re
import socket
import signal
import configparser
from datetime import datetime


def _restore_user_home():
    """HOME/XDG при запуске через sudo/pkexec — до импорта gi."""
    if os.geteuid() != 0:
        return
    home = None
    u = os.environ.get("SUDO_USER")
    if u:
        try:
            home = pwd.getpwnam(u).pw_dir
        except KeyError:
            pass
    else:
        uid = os.environ.get("PKEXEC_UID")
        if uid:
            try:
                home = pwd.getpwuid(int(uid)).pw_dir
            except (KeyError, ValueError):
                pass
    if home and os.path.isdir(home):
        os.environ["HOME"] = home
        for k, v in (("XDG_CONFIG_HOME", ".config"),
                     ("XDG_DATA_HOME", ".local/share"),
                     ("XDG_CACHE_HOME", ".cache")):
            os.environ.setdefault(k, os.path.join(home, v))


_restore_user_home()

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GLib

try:
    from scapy.all import sniff, sendp, Ether, IP, TCP, UDP, ICMP, ARP, Raw, IPv6
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ============================ helpers ============================
def get_network_interfaces():
    try:
        import netifaces
        out = {}
        for i in netifaces.interfaces():
            addrs = netifaces.ifaddresses(i)
            if netifaces.AF_INET in addrs:
                ip = addrs[netifaces.AF_INET][0]['addr']
                if ip != '127.0.0.1':
                    out[i] = ip
        return out
    except ImportError:
        try:
            r = subprocess.run(['ip', '-4', '-o', 'addr', 'show'],
                               capture_output=True, text=True)
            out = {}
            for line in r.stdout.splitlines():
                p = line.split()
                if len(p) >= 7 and p[1] != 'lo' and p[3].split('/')[0] != '127.0.0.1':
                    out[p[1]] = p[3].split('/')[0]
            return out or {'eth0': '192.168.1.x', 'wlan0': '192.168.1.x'}
        except Exception:
            return {'eth0': '192.168.1.x', 'wlan0': '192.168.1.x'}


def is_root():
    return os.geteuid() == 0


def find_exe(name):
    base = os.path.dirname(os.path.abspath(__file__))
    cwd = os.getcwd()
    for p in (os.path.join(base, "bin", name), os.path.join(base, name),
              os.path.join(cwd, "bin", name), os.path.join(cwd, name)):
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def apply_global_gtk_theme():
    s = Gtk.Settings.get_default()
    if s is None:
        return
    paths = []
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        paths.append(os.path.join(xdg, "gtk-3.0", "settings.ini"))
    paths += [os.path.expanduser("~/.config/gtk-3.0/settings.ini"),
              "/etc/gtk-3.0/settings.ini"]
    for p in paths:
        if not os.path.isfile(p):
            continue
        cp = configparser.ConfigParser()
        try:
            cp.read(p)
        except Exception:
            continue
        if not cp.has_section("Settings"):
            continue
        sec = cp["Settings"]
        for key in ("gtk-theme-name", "gtk-icon-theme-name",
                    "gtk-font-name", "gtk-cursor-theme-name"):
            if sec.get(key):
                try:
                    s.set_property(key, sec[key])
                except Exception:
                    pass
        if "gtk-application-prefer-dark-theme" in sec:
            try:
                s.set_property("gtk-application-prefer-dark-theme",
                               sec.getboolean("gtk-application-prefer-dark-theme", False))
            except Exception:
                pass
        break


# ============================ LogWidget ============================
class LogWidget(Gtk.ScrolledWindow):
    def __init__(self, min_height=200):
        super().__init__()
        self.set_min_content_height(min_height)
        self.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        self.set_vexpand(True)
        self.set_hexpand(True)
        self.textview = Gtk.TextView()
        self.textview.set_editable(False)
        self.textview.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.add(self.textview)
        self.buffer = self.textview.get_buffer()
        for name, color in (('timestamp', '#888888'), ('log_info', '#60a5fa'),
                            ('log_success', '#4ade80'), ('log_warning', '#fbbf24'),
                            ('log_error', '#ef4444')):
            self.buffer.create_tag(name, foreground=color)
        self._scroll_timeout = None

    def append(self, msg, level='info'):
        ts = datetime.now().strftime('%H:%M:%S')
        b = self.buffer
        b.insert_with_tags_by_name(b.get_end_iter(), f"[{ts}] ", 'timestamp')
        b.insert_with_tags_by_name(b.get_end_iter(), msg + '\n', f'log_{level}')
        if self._scroll_timeout is not None:
            GLib.source_remove(self._scroll_timeout)
        self._scroll_timeout = GLib.timeout_add(50, self._do_scroll)

    def _do_scroll(self):
        self._scroll_timeout = None
        a = self.get_allocation()
        if a.width > 1 and a.height > 1:
            self.textview.scroll_to_iter(self.buffer.get_end_iter(), 0.0, False, 0, 0)
        return False

    def append_safe(self, msg, level='info'):
        GLib.idle_add(self.append, msg, level)

    def get_buffer(self):
        return self.buffer


# ============================ PacketEditorDialog ============================
class PacketEditorDialog(Gtk.Dialog):
    def __init__(self, parent, packet, callback):
        super().__init__(title="Редактор пакета", transient_for=parent, modal=True)
        self.set_default_size(800, 700)
        self.packet = packet
        self.callback = callback
        self.edited_packet = None
        self.tcp_flags = {}
        self._build()
        self._parse()
        self.show_all()

    @staticmethod
    def _grid(container):
        g = Gtk.Grid()
        for fn in (g.set_column_spacing, g.set_row_spacing):
            fn(5)
        for fn in (g.set_margin_start, g.set_margin_end,
                   g.set_margin_top, g.set_margin_bottom):
            fn(5)
        container.add(g)
        return g

    @staticmethod
    def _row(grid, row, label, widget):
        grid.attach(Gtk.Label(label=label), 0, row, 1, 1)
        grid.attach(widget, 1, row, 1, 1)

    def _build(self):
        v = self.get_content_area()
        v.set_spacing(5)
        for fn in (v.set_margin_start, v.set_margin_end,
                   v.set_margin_top, v.set_margin_bottom):
            fn(10)

        # Ethernet
        f = Gtk.Frame(label="Ethernet"); v.pack_start(f, False, False, 0)
        g = self._grid(f)
        self.eth_src = Gtk.Entry(); self.eth_src.set_width_chars(17)
        self.eth_dst = Gtk.Entry(); self.eth_dst.set_width_chars(17)
        self._row(g, 0, "Source MAC:", self.eth_src)
        self._row(g, 1, "Dest MAC:", self.eth_dst)

        # IP
        f = Gtk.Frame(label="IP"); v.pack_start(f, False, False, 0)
        g = self._grid(f)
        self.ip_src = Gtk.Entry(); self.ip_src.set_width_chars(15)
        self.ip_dst = Gtk.Entry(); self.ip_dst.set_width_chars(15)
        self.ip_ttl = Gtk.Entry(); self.ip_ttl.set_width_chars(5)
        self._row(g, 0, "Source IP:", self.ip_src)
        self._row(g, 1, "Dest IP:", self.ip_dst)
        self._row(g, 2, "TTL:", self.ip_ttl)

        # Transport
        f = Gtk.Frame(label="Transport"); v.pack_start(f, False, False, 0)
        g = self._grid(f)
        self.proto_combo = Gtk.ComboBoxText()
        for p in ("TCP", "UDP", "ICMP", "RAW"):
            self.proto_combo.append_text(p)
        self.proto_combo.set_active(0)
        self.src_port = Gtk.Entry(); self.src_port.set_width_chars(6)
        self.dst_port = Gtk.Entry(); self.dst_port.set_width_chars(6)
        self._row(g, 0, "Protocol:", self.proto_combo)
        self._row(g, 1, "Source Port:", self.src_port)
        self._row(g, 2, "Dest Port:", self.dst_port)

        # TCP flags
        f = Gtk.Frame(label="TCP Flags"); v.pack_start(f, False, False, 0)
        box = Gtk.Box(spacing=5)
        for fn in (box.set_margin_start, box.set_margin_end,
                   box.set_margin_top, box.set_margin_bottom):
            fn(5)
        for name in ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"):
            cb = Gtk.CheckButton(label=name)
            box.pack_start(cb, False, False, 0)
            self.tcp_flags[name] = cb
        f.add(box)

        # Payload
        f = Gtk.Frame(label="Payload (hex)"); v.pack_start(f, True, True, 0)
        self.payload_text = Gtk.TextView()
        self.payload_text.set_wrap_mode(Gtk.WrapMode.WORD)
        sc = Gtk.ScrolledWindow()
        sc.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        sc.set_min_content_height(150); sc.set_vexpand(True)
        sc.add(self.payload_text); f.add(sc)

        # Buttons
        box = Gtk.Box(spacing=10)
        for fn in (box.set_margin_start, box.set_margin_end,
                   box.set_margin_top, box.set_margin_bottom):
            fn(10)
        ok = Gtk.Button.new_with_label("Применить"); ok.connect("clicked", self.on_apply)
        no = Gtk.Button.new_with_label("Отмена");    no.connect("clicked", lambda *_: self.destroy())
        box.pack_start(ok, False, False, 0); box.pack_start(no, False, False, 0)
        v.pack_start(box, False, False, 0)

    def _parse(self):
        if not SCAPY_AVAILABLE:
            return
        p = self.packet
        if p.haslayer(Ether):
            self.eth_src.set_text(p[Ether].src)
            self.eth_dst.set_text(p[Ether].dst)
        ip = p[IP] if p.haslayer(IP) else (p[IPv6] if p.haslayer(IPv6) else None)
        if ip:
            self.ip_src.set_text(ip.src); self.ip_dst.set_text(ip.dst)
            self.ip_ttl.set_text(str(getattr(ip, 'ttl', getattr(ip, 'hlim', ''))))
        if p.haslayer(TCP):
            self.proto_combo.set_active(0)
            self.src_port.set_text(str(p[TCP].sport))
            self.dst_port.set_text(str(p[TCP].dport))
            flags = p[TCP].flags
            fmap = {'FIN': 0x01, 'SYN': 0x02, 'RST': 0x04, 'PSH': 0x08,
                    'ACK': 0x10, 'URG': 0x20, 'ECE': 0x40, 'CWR': 0x80}
            for n, cb in self.tcp_flags.items():
                cb.set_active(bool(flags & fmap[n]))
        elif p.haslayer(UDP):
            self.proto_combo.set_active(1)
            self.src_port.set_text(str(p[UDP].sport))
            self.dst_port.set_text(str(p[UDP].dport))
        elif p.haslayer(ICMP):
            self.proto_combo.set_active(2)
        if p.haslayer(Raw):
            self.payload_text.get_buffer().set_text(p[Raw].load.hex(), -1)

    def on_apply(self, *_):
        try:
            self.edited_packet = self.packet
            self.callback(self.edited_packet, True)
            self.destroy()
        except Exception as e:
            d = Gtk.MessageDialog(transient_for=self, flags=0,
                                  message_type=Gtk.MessageType.ERROR,
                                  buttons=Gtk.ButtonsType.OK,
                                  text="Ошибка редактирования")
            d.format_secondary_text(str(e)); d.run(); d.destroy()


# ============================ Main app ============================
class GotchaGTK:
    def __init__(self):
        self.interfaces = get_network_interfaces()
        self.iface_list = list(self.interfaces.keys())
        self.attack_running = False
        self.current_process = None
        self.current_log = None
        self.current_status = None
        self.stop_event = threading.Event()
        self.sniffing_running = False
        self.sniff_thread = None
        self.captured_packets = []
        self.edited_packet = None
        self.packet_counter = 0
        self.response_counter = 0
        self.sniff_stop = threading.Event()
        self.access_running = False
        self.dhcp_stats = {'start_time': 0, 'sent_packets': 0, 'unique_macs': 0,
                           'last_update': 0, 'last_sent': 0}
        self.dhcp_offered_ips = set()
        self.dhcp_lock = threading.Lock()
        self.arp_stats = {'start_time': 0, 'sent_packets': 0,
                          'last_update': 0, 'last_sent': 0}
        self.dos_stats = {'start_time': 0, 'sent_packets': 0,
                          'last_update': 0, 'last_sent': 0}
        self.dns_stats = {'start_time': 0, 'intercepted': 0, 'spoofed': 0,
                          'last_update': 0, 'last_spoofed': 0}
        self.mac_stats = {'start_time': 0, 'sent_frames': 0,
                          'last_update': 0, 'last_sent': 0}
        self.stats_timers = {}
        self.build_gui()
        self.root.connect("destroy", self.on_closing)

    # ---------- GUI primitives ----------
    def create_num_entry(self, default='0', min_chars=6, max_chars=12):
        e = Gtk.Entry()
        e.set_text(str(default))
        e.set_width_chars(min_chars); e.set_max_width_chars(max_chars)
        e.set_hexpand(False); e.set_halign(Gtk.Align.START)

        def _ch(_):
            need = max(min_chars, min(max_chars, len(e.get_text()) + 1))
            if e.get_width_chars() != need:
                e.set_width_chars(need)
        e.connect("changed", _ch)
        return e

    def create_text_entry(self, default='', chars=15):
        e = Gtk.Entry()
        e.set_text(default); e.set_width_chars(chars)
        e.set_hexpand(False); e.set_halign(Gtk.Align.START)
        return e

    def create_iface_combo(self):
        c = Gtk.ComboBoxText()
        for i in self.iface_list:
            c.append_text(i)
        if self.iface_list:
            c.set_active(0)
        c.set_hexpand(False); c.set_halign(Gtk.Align.START)
        return c

    def create_attack_controls(self, start_cb, stop_cb):
        box = Gtk.Box(spacing=5)
        box.set_margin_top(10); box.set_margin_bottom(10)
        start = Gtk.Button.new_with_label("Запустить"); start.connect("clicked", start_cb)
        stop = Gtk.Button.new_with_label("Остановить"); stop.connect("clicked", stop_cb)
        stop.set_sensitive(False)
        box.pack_start(start, False, False, 0)
        box.pack_start(stop, False, False, 0)
        return box, start, stop

    def add_save_log_button(self, parent, log_widget):
        b = Gtk.Button.new_with_label("Сохранить лог")
        b.connect("clicked", lambda *_: self.save_log(log_widget))
        parent.pack_start(b, False, False, 0)
        return b

    # -------- tab scaffolding helpers --------
    @staticmethod
    def _setup_tab():
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        for fn in (tab.set_margin_start, tab.set_margin_end,
                   tab.set_margin_top, tab.set_margin_bottom):
            fn(10)
        return scroll, tab

    @staticmethod
    def _setup_grid(parent, col=10, row=5):
        g = Gtk.Grid()
        g.set_column_spacing(col); g.set_row_spacing(row)
        g.set_halign(Gtk.Align.START)
        for fn in (g.set_margin_start, g.set_margin_end,
                   g.set_margin_top, g.set_margin_bottom):
            fn(5)
        if isinstance(parent, Gtk.Box):
            parent.pack_start(g, False, False, 0)
        else:
            parent.add(g)
        return g

    @staticmethod
    def _row(grid, r, label, widget):
        grid.attach(Gtk.Label(label=label), 0, r, 1, 1)
        grid.attach(widget, 1, r, 1, 1)

    @staticmethod
    def _stats_frame():
        f = Gtk.Frame(label="Статистика")
        g = Gtk.Grid()
        g.set_column_spacing(10); g.set_row_spacing(5)
        for fn in (g.set_margin_start, g.set_margin_end,
                   g.set_margin_top, g.set_margin_bottom):
            fn(5)
        g.set_halign(Gtk.Align.START)
        f.add(g)
        return f, g

    @staticmethod
    def _stat(grid, r, label):
        grid.attach(Gtk.Label(label=label), 0, r, 1, 1)
        v = Gtk.Label(label="0")
        grid.attach(v, 1, r, 1, 1)
        return v

    @staticmethod
    def _status_box(parent):
        box = Gtk.Box(spacing=5)
        box.pack_start(Gtk.Label(label="Статус:"), False, False, 0)
        s = Gtk.Label(label="Ожидание...")
        box.pack_start(s, False, False, 0)
        parent.pack_start(box, False, False, 0)
        return s

    def _finish_tab(self, scroll, tab, log_widget, title):
        tab.pack_start(log_widget, True, True, 0)
        self.add_save_log_button(tab, log_widget)
        scroll.add(tab)
        self.notebook.append_page(scroll, Gtk.Label(label=title))

    # ---------- main window ----------
    def build_gui(self):
        apply_global_gtk_theme()
        self.root = Gtk.Window(title="Gotcha Linux")
        self.root.set_default_size(1200, 800)
        self.root.set_size_request(800, 600)
        self.root.set_position(Gtk.WindowPosition.CENTER)

        main = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        for fn in (main.set_margin_start, main.set_margin_end,
                   main.set_margin_top, main.set_margin_bottom):
            fn(10)
        self.root.add(main)

        h = Gtk.Label()
        h.set_markup("<span size='x-large' weight='bold'>Gotcha Linux</span>")
        main.pack_start(h, False, False, 0)

        self.notebook = Gtk.Notebook()
        self.notebook.set_vexpand(True); self.notebook.set_hexpand(True)
        main.pack_start(self.notebook, True, True, 0)

        self.create_access_tab()
        self.create_intercept_tab()
        self.create_dhcp_tab()
        self.create_arp_tab()
        self.create_dos_tab()
        self.create_dns_tab()
        self.create_mac_tab()
        self.create_help_tab()

        sbox = Gtk.Box(spacing=5); sbox.set_margin_top(5)
        main.pack_start(sbox, False, False, 0)
        self.status_var = Gtk.Label(label="Готов к работе")
        self.status_var.set_halign(Gtk.Align.START)
        self.status_var.set_valign(Gtk.Align.CENTER)
        self.status_var.set_hexpand(True)
        sbox.pack_start(self.status_var, True, True, 0)
        sa = Gtk.Button.new_with_label("Остановить все"); sa.connect("clicked", self.stop_all)
        qb = Gtk.Button.new_with_label("Выход");          qb.connect("clicked", self.on_closing)
        sbox.pack_start(sa, False, False, 0); sbox.pack_start(qb, False, False, 0)
        self.root.show_all()

    def show_warning(self, title, msg):
        d = Gtk.MessageDialog(transient_for=self.root, flags=0,
                              message_type=Gtk.MessageType.WARNING,
                              buttons=Gtk.ButtonsType.OK, text=title)
        d.format_secondary_text(msg); d.run(); d.destroy()

    def save_log(self, log_widget):
        d = Gtk.FileChooserDialog(
            title="Сохранить лог", parent=self.root,
            action=Gtk.FileChooserAction.SAVE,
            buttons=(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                     Gtk.STOCK_SAVE, Gtk.ResponseType.OK))
        d.set_current_name("log.txt")
        if d.run() == Gtk.ResponseType.OK:
            fn = d.get_filename()
            if fn:
                try:
                    b = log_widget.get_buffer()
                    text = b.get_text(b.get_start_iter(), b.get_end_iter(), False)
                    with open(fn, 'w', encoding='utf-8') as f:
                        f.write(text)
                    self.status_var.set_label("Лог сохранён")
                except Exception as e:
                    self.show_warning("Ошибка", f"Не удалось сохранить: {e}")
        d.destroy()

    # ---------- running external binaries ----------
    def run_binary(self, bin_name, args, log_widget, status_label, start_btn, stop_btn):
        if self.attack_running:
            return
        path = find_exe(bin_name)
        if not path:
            log_widget.append_safe(f'Ошибка: бинарник {bin_name} не найден', 'error')
            self.show_warning("Ошибка", f"Бинарник {bin_name} не найден.\nПроверьте папку bin/.")
            return
        cmd = [path] + args
        log_widget.append_safe(f'Запуск: {" ".join(cmd)}', 'info')
        self.attack_running = True
        self.stop_event.clear()
        self.current_log, self.current_status = log_widget, status_label
        status_label.set_label("Запущен...")
        self.status_var.set_label("Атака выполняется...")
        start_btn.set_sensitive(False); stop_btn.set_sensitive(True)

        def worker():
            try:
                self.current_process = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    encoding='utf-8', errors='replace', bufsize=1,
                    preexec_fn=os.setsid if os.name != 'nt' else None)
                log_widget.append_safe(f'Процесс запущен (PID={self.current_process.pid})', 'success')
                for line in iter(self.current_process.stdout.readline, ''):
                    if self.stop_event.is_set():
                        break
                    if line.strip():
                        log_widget.append_safe(line.rstrip(), 'info')
                        self._parse_stats(line.rstrip())
                self.current_process.stdout.close()
                rc = self.current_process.wait()
                if self.stop_event.is_set():
                    log_widget.append_safe('Атака остановлена пользователем', 'warning')
                    status_label.set_label("Остановлено")
                elif rc == 0:
                    status_label.set_label("Завершено")
                else:
                    log_widget.append_safe(f'Бинарник завершён с ошибкой (код {rc})', 'error')
                    status_label.set_label("Ошибка")
            except Exception as e:
                log_widget.append_safe(f'Ошибка: {e}', 'error')
                status_label.set_label("Ошибка")
            finally:
                self.attack_running = False
                self.current_process = None
                self.status_var.set_label("Готов")
                start_btn.set_sensitive(True); stop_btn.set_sensitive(False)

        threading.Thread(target=worker, daemon=True).start()

    def stop_binary(self, log_widget, status_label):
        if not self.attack_running or self.current_process is None:
            return
        self.stop_event.set()
        self.status_var.set_label("Остановка...")
        status_label.set_label("Остановка...")
        try:
            if os.name != 'nt':
                os.killpg(os.getpgid(self.current_process.pid), signal.SIGKILL)
            else:
                self.current_process.kill()
            log_widget.append_safe('Отправлен SIGKILL процессу', 'warning')
            try:
                self.current_process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
        except Exception as e:
            log_widget.append_safe(f'Ошибка при остановке: {e}', 'error')
        time.sleep(0.5)

    def stop_all(self, *_):
        if self.attack_running and self.current_log and self.current_status:
            self.stop_binary(self.current_log, self.current_status)
        if self.sniffing_running:
            self.stop_sniff(None)
        self.status_var.set_label("Остановлено все")

    # ---------- stats parsing ----------
    def _parse_stats(self, line):
        if "[CAPTURED]" in line:
            m = re.search(r"->\s*([\d.]+)", line)
            if m:
                with self.dhcp_lock:
                    self.dhcp_offered_ips.add(m.group(1))
                self._update_dhcp_stats()
        elif "[STATS]" in line:
            s = re.search(r"Sent:\s*(\d+)", line)
            u = re.search(r"Unique MACs:\s*(\d+)", line)
            if s: self.dhcp_stats['sent_packets'] = int(s.group(1))
            if u: self.dhcp_stats['unique_macs'] = int(u.group(1))
            self._update_dhcp_stats()
        if "Sent Discover" in line:
            self.dhcp_stats['sent_packets'] += 1; self._update_dhcp_stats()
        if "Sending ARP" in line:
            self.arp_stats['sent_packets'] += 1; self._update_arp_stats()
        if "Packets:" in line:
            m = re.search(r"Packets:\s*(\d+)", line)
            if m:
                self.dos_stats['sent_packets'] = int(m.group(1)); self._update_dos_stats()
        if "PPS:" in line:
            m = re.search(r"PPS:\s*([\d.]+)", line)
            if m:
                try:
                    self.dos_rate_label.set_text(str(int(float(m.group(1)))))
                except Exception:
                    pass
        if "DNS Query detected" in line:
            self.dns_stats['intercepted'] += 1
        if "SPOOFING" in line or "CATCH-ALL" in line:
            self.dns_stats['spoofed'] += 1; self._update_dns_stats()
        if "Sent" in line and "packets" in line:
            m = re.search(r"Sent\s+(\d+)\s+packets", line)
            if m:
                self.mac_stats['sent_frames'] += int(m.group(1)); self._update_mac_stats()
        if "Flood finished" in line:
            self._update_mac_stats()

    @staticmethod
    def _fmt_time(duration):
        h = int(duration // 3600); m = int((duration % 3600) // 60); s = int(duration % 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    def _upd_stats(self, kind):
        if kind == 'dhcp':
            if not getattr(self, 'dhcp_attack_running', False):
                return None
            key, last = 'sent_packets', 'last_sent'
        else:
            if not getattr(self, f'{kind}_running', False):
                return None
            key = 'spoofed' if kind == 'dns' else ('sent_frames' if kind == 'mac' else 'sent_packets')
            last = 'last_spoofed' if kind == 'dns' else 'last_sent'
        stats = getattr(self, f'{kind}_stats')
        now = time.time()
        dur = now - stats['start_time']
        delta = now - stats['last_update']
        if delta >= 1:
            rate = (stats[key] - stats.get(last, 0)) / delta
            getattr(self, f'{kind}_rate_label').set_text(str(int(rate)))
            stats['last_update'] = now
            stats[last] = stats[key]
            getattr(self, f'{kind}_time_label').set_text(self._fmt_time(dur))
        return stats

    def _update_dhcp_stats(self):
        s = self._upd_stats('dhcp')
        if s is None:
            return
        self.dhcp_sent_label.set_text(str(s['sent_packets']))
        self.dhcp_unique_label.set_text(str(s['unique_macs']))
        with self.dhcp_lock:
            self.dhcp_ips_label.set_text(str(len(self.dhcp_offered_ips)))

    def _update_arp_stats(self):
        s = self._upd_stats('arp')
        if s: self.arp_sent_label.set_text(str(s['sent_packets']))

    def _update_dos_stats(self):
        s = self._upd_stats('dos')
        if s: self.dos_sent_label.set_text(str(s['sent_packets']))

    def _update_dns_stats(self):
        s = self._upd_stats('dns')
        if s:
            self.dns_intercepted_label.set_text(str(s['intercepted']))
            self.dns_spoofed_label.set_text(str(s['spoofed']))

    def _update_mac_stats(self):
        s = self._upd_stats('mac')
        if s: self.mac_sent_label.set_text(str(s['sent_frames']))

    def start_stats_timer(self, name):
        if name in self.stats_timers:
            GLib.source_remove(self.stats_timers[name])
        self.stats_timers[name] = GLib.timeout_add_seconds(1, self._update_stats_cb, name)

    def _update_stats_cb(self, name):
        getattr(self, f'_update_{name}_stats')()
        return True

    # ================= Вкладка "Доступ" =================
    def create_access_tab(self):
        scroll, tab = self._setup_tab()
        frame = Gtk.Frame(label="Базовые функции доступа")
        tab.pack_start(frame, False, False, 0)
        g = self._setup_grid(frame)
        self.access_ip = self.create_text_entry("192.168.1.1", 15)
        self.access_iface = self.create_iface_combo()
        self._row(g, 0, "IP адрес:", self.access_ip)
        self._row(g, 1, "Интерфейс:", self.access_iface)

        fl = Gtk.FlowBox()
        fl.set_valign(Gtk.Align.START)
        fl.set_max_children_per_line(10)
        fl.set_min_children_per_line(2)
        fl.set_selection_mode(Gtk.SelectionMode.NONE)
        fl.set_column_spacing(5); fl.set_row_spacing(5)
        for label, cb in (("ICMP Ping", self.on_ping), ("Port Scan", self.on_port_scan),
                          ("Traceroute", self.on_traceroute),
                          ("Таблица маршрутизации", self.on_route),
                          ("Сетевые адаптеры", self.on_adapters),
                          ("Сканировать сеть", self.on_net_scan)):
            b = Gtk.Button.new_with_label(label); b.connect("clicked", cb); fl.add(b)
        tab.pack_start(fl, False, False, 0)

        out = Gtk.Frame(label="Результаты"); out.set_vexpand(True)
        self.access_log = LogWidget(200); out.add(self.access_log)
        tab.pack_start(out, True, True, 0)
        self.add_save_log_button(tab, self.access_log)

        scroll.add(tab)
        self.notebook.append_page(scroll, Gtk.Label(label="Доступ"))

    def _run_access_cmd(self, cmd, log_msg):
        if self.access_running:
            self.access_log.append_safe("Операция уже выполняется, подождите...", 'warning')
            return
        self.access_running = True
        self.access_log.append_safe(log_msg, 'info')

        def worker():
            try:
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     encoding='utf-8', errors='replace', bufsize=1)
                for line in iter(p.stdout.readline, ''):
                    if line.strip():
                        self.access_log.append_safe(line.rstrip(), 'info')
                p.wait()
            except Exception as e:
                self.access_log.append_safe(f"Ошибка: {e}", 'error')
            finally:
                self.access_running = False

        threading.Thread(target=worker, daemon=True).start()

    def on_ping(self, *_):
        ip = self.access_ip.get_text().strip()
        if not ip:
            self.access_log.append_safe("Введите IP", 'error'); return
        self._run_access_cmd(['ping', '-c', '4', ip], f"Ping {ip}...")

    def on_port_scan(self, *_):
        ip = self.access_ip.get_text().strip()
        if not ip:
            self.access_log.append_safe("Введите IP", 'error'); return
        if self.access_running:
            self.access_log.append_safe("Операция уже выполняется, подождите...", 'warning'); return
        self.access_running = True
        self.access_log.append_safe(f"Port scan {ip}...", 'info')

        def worker():
            try:
                for p in (21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389):
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    if s.connect_ex((ip, p)) == 0:
                        self.access_log.append_safe(f"Порт {p} открыт", 'success')
                    s.close()
                self.access_log.append_safe("Сканирование завершено", 'info')
            except Exception as e:
                self.access_log.append_safe(f"Ошибка: {e}", 'error')
            finally:
                self.access_running = False

        threading.Thread(target=worker, daemon=True).start()

    def on_traceroute(self, *_):
        ip = self.access_ip.get_text().strip()
        if not ip:
            self.access_log.append_safe("Введите IP", 'error'); return
        self._run_access_cmd(['traceroute', '-n', '-m', '30', '-w', '1', ip],
                             f"Traceroute {ip}...")

    def on_route(self, *_):
        self._run_access_cmd(['ip', 'route'], "=== Таблица маршрутизации ===")

    def on_adapters(self, *_):
        self._run_access_cmd(['ip', 'addr', 'show'], "=== Сетевые адаптеры ===")

    def on_net_scan(self, *_):
        ip = self.access_ip.get_text().strip()
        if not ip:
            self.access_log.append_safe("Введите IP", 'error'); return
        if self.access_running:
            self.access_log.append_safe("Операция уже выполняется, подождите...", 'warning'); return
        self.access_running = True
        self.access_log.append_safe(f"Сканирование сети {ip}/24...", 'info')

        def worker():
            try:
                if not SCAPY_AVAILABLE:
                    self.access_log.append_safe("Scapy не установлен", 'error'); return
                from scapy.all import ARP, Ether, srp
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip + "/24"),
                             timeout=2, verbose=0)
                self.access_log.append_safe(f"Найдено {len(ans)} хостов:", 'success')
                for _, rcv in ans:
                    self.access_log.append_safe(f"{rcv.psrc}  {rcv.hwsrc}", 'info')
            except Exception as e:
                self.access_log.append_safe(f"Ошибка: {e}", 'error')
            finally:
                self.access_running = False

        threading.Thread(target=worker, daemon=True).start()

    # ================= DHCP Starvation =================
    def create_dhcp_tab(self):
        scroll, tab = self._setup_tab()
        g = self._setup_grid(tab)
        self.dhcp_iface = self.create_iface_combo()
        self.dhcp_pool = self.create_num_entry("254")
        self.dhcp_count = self.create_num_entry("1000")
        self.dhcp_delay = self.create_num_entry("0.05")
        self.dhcp_offer = self.create_num_entry("30")
        self.dhcp_ack = self.create_num_entry("5")
        for i, (lbl, w) in enumerate((
                ("Интерфейс:", self.dhcp_iface),
                ("Размер пула:", self.dhcp_pool),
                ("Кол-во запросов:", self.dhcp_count),
                ("Задержка (сек):", self.dhcp_delay),
                ("Таймаут Offer (сек):", self.dhcp_offer),
                ("Таймаут ACK (сек):", self.dhcp_ack))):
            self._row(g, i, lbl, w)

        c, self.dhcp_start_btn, self.dhcp_stop_btn = self.create_attack_controls(
            self.start_dhcp, self.stop_dhcp)
        tab.pack_start(c, False, False, 0)

        sf, sg = self._stats_frame()
        self.dhcp_sent_label = self._stat(sg, 0, "Отправлено пакетов:")
        self.dhcp_unique_label = self._stat(sg, 1, "Уникальных MAC:")
        self.dhcp_ips_label = self._stat(sg, 2, "Захвачено IP:")
        self.dhcp_rate_label = self._stat(sg, 3, "Скорость (pps):")
        self.dhcp_time_label = self._stat(sg, 4, "Время работы:")
        self.dhcp_time_label.set_text("00:00:00")
        tab.pack_start(sf, False, False, 0)

        self.dhcp_status = self._status_box(tab)
        self.dhcp_log = LogWidget(200)
        self._finish_tab(scroll, tab, self.dhcp_log, "DHCP Starvation")
        self.dhcp_attack_running = False

    def start_dhcp(self, *_):
        self.dhcp_attack_running = True
        self.dhcp_stats['start_time'] = time.time()
        self.dhcp_stats['sent_packets'] = 0
        self.dhcp_offered_ips.clear()
        args = [self.dhcp_iface.get_active_text(), self.dhcp_pool.get_text(),
                self.dhcp_count.get_text(), self.dhcp_delay.get_text(),
                self.dhcp_offer.get_text(), self.dhcp_ack.get_text()]
        self.run_binary('DHCPstarvation', args, self.dhcp_log, self.dhcp_status,
                        self.dhcp_start_btn, self.dhcp_stop_btn)
        self.start_stats_timer('dhcp')

    def stop_dhcp(self, *_):
        self.dhcp_attack_running = False
        self.stop_binary(self.dhcp_log, self.dhcp_status)

    # ================= ARP Spoofing =================
    def create_arp_tab(self):
        scroll, tab = self._setup_tab()
        g = self._setup_grid(tab)
        self.arp_target = self.create_text_entry("192.168.1.100", 15)
        self.arp_gateway = self.create_text_entry("192.168.1.1", 15)
        self.arp_iface = self.create_iface_combo()
        self.arp_interval = self.create_num_entry("2")
        for i, (lbl, w) in enumerate((
                ("Целевой IP:", self.arp_target),
                ("Шлюз:", self.arp_gateway),
                ("Интерфейс:", self.arp_iface),
                ("Интервал (сек):", self.arp_interval))):
            self._row(g, i, lbl, w)

        c, self.arp_start_btn, self.arp_stop_btn = self.create_attack_controls(
            self.start_arp, self.stop_arp)
        tab.pack_start(c, False, False, 0)

        sf, sg = self._stats_frame()
        self.arp_sent_label = self._stat(sg, 0, "Отправлено пакетов:")
        self.arp_rate_label = self._stat(sg, 1, "Скорость (pps):")
        self.arp_time_label = self._stat(sg, 2, "Время работы:")
        self.arp_time_label.set_text("00:00:00")
        tab.pack_start(sf, False, False, 0)

        self.arp_status = self._status_box(tab)
        self.arp_log = LogWidget(200)
        self._finish_tab(scroll, tab, self.arp_log, "ARP Spoofing")
        self.arp_running = False

    def start_arp(self, *_):
        self.arp_running = True
        self.arp_stats['start_time'] = time.time()
        self.arp_stats['sent_packets'] = 0
        args = [self.arp_iface.get_active_text(), self.arp_target.get_text(),
                self.arp_gateway.get_text(), self.arp_interval.get_text()]
        self.run_binary('ARPspoof', args, self.arp_log, self.arp_status,
                        self.arp_start_btn, self.arp_stop_btn)
        self.start_stats_timer('arp')

    def stop_arp(self, *_):
        self.arp_running = False
        self.stop_binary(self.arp_log, self.arp_status)

    # ================= DoS атака =================
    def create_dos_tab(self):
        scroll, tab = self._setup_tab()
        g = self._setup_grid(tab)
        self.dos_ip = self.create_text_entry("192.168.1.1", 15)
        self.dos_proto = Gtk.ComboBoxText()
        for p in ("TCP", "UDP", "ICMP", "ARP"):
            self.dos_proto.append_text(p)
        self.dos_proto.set_active(0)
        self.dos_port = self.create_num_entry("80")
        self.dos_size = self.create_num_entry("1024")
        self.dos_mac = self.create_text_entry("ff:ff:ff:ff:ff:ff", 17)
        self.dos_duration = self.create_num_entry("60")
        self.dos_threads = self.create_num_entry("4")
        self.dos_iface = self.create_iface_combo()
        for i, (lbl, w) in enumerate((
                ("IP адрес:", self.dos_ip),
                ("Протокол:", self.dos_proto),
                ("Порт:", self.dos_port),
                ("Размер пакета:", self.dos_size),
                ("MAC назначения:", self.dos_mac),
                ("Время (сек):", self.dos_duration),
                ("Потоки (threads):", self.dos_threads),
                ("Интерфейс:", self.dos_iface))):
            self._row(g, i, lbl, w)

        cb = Gtk.Box(spacing=10)
        self.dos_random_ip = Gtk.CheckButton(label="Случайный IP")
        self.dos_random_mac = Gtk.CheckButton(label="Случайный MAC")
        cb.pack_start(self.dos_random_ip, False, False, 0)
        cb.pack_start(self.dos_random_mac, False, False, 0)
        g.attach(cb, 0, 8, 2, 1)

        c, self.dos_start_btn, self.dos_stop_btn = self.create_attack_controls(
            self.start_dos, self.stop_dos)
        tab.pack_start(c, False, False, 0)

        sf, sg = self._stats_frame()
        self.dos_sent_label = self._stat(sg, 0, "Отправлено пакетов:")
        self.dos_rate_label = self._stat(sg, 1, "Скорость (pps):")
        self.dos_time_label = self._stat(sg, 2, "Время работы:")
        self.dos_time_label.set_text("00:00:00")
        tab.pack_start(sf, False, False, 0)

        self.dos_status = self._status_box(tab)
        self.dos_log = LogWidget(200)
        self._finish_tab(scroll, tab, self.dos_log, "DoS атака")
        self.dos_running = False

    def start_dos(self, *_):
        self.dos_running = True
        self.dos_stats['start_time'] = time.time()
        self.dos_stats['sent_packets'] = 0
        proto = self.dos_proto.get_active_text().lower()
        bin_name = {'tcp': 'NPtcpT', 'udp': 'NPudpT',
                    'icmp': 'NPicmpT', 'arp': 'NParpT'}.get(proto)
        if not bin_name:
            self.dos_log.append_safe('Неизвестный протокол', 'error'); return
        iface = self.dos_iface.get_active_text()
        src_ip = self.interfaces.get(iface, '192.168.1.x')
        try:
            threads = max(1, min(256, int(self.dos_threads.get_text().strip() or "4")))
        except ValueError:
            threads = 4
        args = [src_ip, self.dos_ip.get_text(), self.dos_port.get_text(),
                str(threads), self.dos_duration.get_text()]
        if self.dos_random_ip.get_active():
            args.append('--random-ip')
        if self.dos_random_mac.get_active():
            args.append('--random-mac')
        args += ['--packet-size', self.dos_size.get_text()]
        if self.dos_mac.get_text() != 'ff:ff:ff:ff:ff:ff':
            args.append(self.dos_mac.get_text())
        self.dos_log.append_safe(f'Потоков: {threads}', 'info')
        self.run_binary(bin_name, args, self.dos_log, self.dos_status,
                        self.dos_start_btn, self.dos_stop_btn)
        self.start_stats_timer('dos')

    def stop_dos(self, *_):
        self.dos_running = False
        self.stop_binary(self.dos_log, self.dos_status)

    # ================= DNS Spoofing =================
    def create_dns_tab(self):
        scroll, tab = self._setup_tab()
        g = self._setup_grid(tab)
        self.dns_iface = self.create_iface_combo()
        self.dns_ttl = self.create_num_entry("5")
        self.dns_victim_ip = self.create_text_entry("192.168.0.191", 15)
        self.dns_gateway_ip = self.create_text_entry("192.168.0.1", 15)
        for i, (lbl, w) in enumerate((
                ("Интерфейс:", self.dns_iface),
                ("TTL (сек):", self.dns_ttl),
                ("IP жертвы:", self.dns_victim_ip),
                ("IP шлюза:", self.dns_gateway_ip))):
            self._row(g, i, lbl, w)
        self.dns_catchall = Gtk.CheckButton(label="Подменять все запросы (catch-all)")
        g.attach(self.dns_catchall, 0, 4, 2, 1)

        c, self.dns_start_btn, self.dns_stop_btn = self.create_attack_controls(
            self.start_dns, self.stop_dns)
        tab.pack_start(c, False, False, 0)

        rf = Gtk.Frame(label="Правила подмены (домен → IP)")
        tab.pack_start(rf, False, False, 0)
        rg = self._setup_grid(rf, col=10, row=5)
        self.dns_domain_entry = self.create_text_entry("", 20)
        self.dns_ip_entry = self.create_text_entry("", 15)
        self._row(rg, 0, "Домен:", self.dns_domain_entry)
        self._row(rg, 1, "IP:", self.dns_ip_entry)
        btns = Gtk.Box(spacing=5)
        ad = Gtk.Button.new_with_label("Добавить"); ad.connect("clicked", self.add_dns_rule)
        rm = Gtk.Button.new_with_label("Удалить");  rm.connect("clicked", self.del_dns_rule)
        btns.pack_start(ad, False, False, 0); btns.pack_start(rm, False, False, 0)
        rg.attach(btns, 0, 2, 2, 1)

        self.dns_rules_store = Gtk.ListStore(str, str)
        self.dns_rules_tree = Gtk.TreeView(model=self.dns_rules_store)
        self.dns_rules_tree.append_column(
            Gtk.TreeViewColumn("Домен (маска *)", Gtk.CellRendererText(), text=0))
        self.dns_rules_tree.append_column(
            Gtk.TreeViewColumn("IP адрес", Gtk.CellRendererText(), text=1))
        sc = Gtk.ScrolledWindow()
        sc.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        sc.set_min_content_height(100); sc.add(self.dns_rules_tree)
        rg.attach(sc, 0, 3, 2, 1)

        sf, sg = self._stats_frame()
        self.dns_intercepted_label = self._stat(sg, 0, "Перехвачено:")
        self.dns_spoofed_label = self._stat(sg, 1, "Подменено:")
        self.dns_rate_label = self._stat(sg, 2, "Скорость (spoof/s):")
        self.dns_time_label = self._stat(sg, 3, "Время работы:")
        self.dns_time_label.set_text("00:00:00")
        tab.pack_start(sf, False, False, 0)

        self.dns_status = self._status_box(tab)
        self.dns_log = LogWidget(200)
        self._finish_tab(scroll, tab, self.dns_log, "DNS Spoofing")
        self.dns_running = False

    def add_dns_rule(self, *_):
        d = self.dns_domain_entry.get_text().strip()
        ip = self.dns_ip_entry.get_text().strip()
        if not d or not ip:
            self.dns_log.append_safe("Введите домен и IP", 'error'); return
        d_clean = d.replace("*.", "").strip(".")
        self.dns_rules_store.append([d_clean, ip])
        self.dns_domain_entry.set_text(""); self.dns_ip_entry.set_text("")
        self.dns_log.append_safe(f"Правило добавлено: {d_clean} -> {ip}", 'success')

    def del_dns_rule(self, *_):
        model, it = self.dns_rules_tree.get_selection().get_selected()
        if it:
            dom = model[it][0]
            model.remove(it)
            self.dns_log.append_safe(f"Правило удалено: {dom}", 'warning')
        else:
            self.dns_log.append_safe("Выберите правило для удаления", 'warning')

    def start_dns(self, *_):
        if self.dns_running:
            self.dns_log.append_safe("DNS Spoofing уже запущен", 'warning'); return
        victim = self.dns_victim_ip.get_text().strip()
        gateway = self.dns_gateway_ip.get_text().strip()
        if not victim or not gateway:
            self.dns_log.append_safe("Укажите IP жертвы и IP шлюза", 'error'); return
        rules = [(r[0], r[1]) for r in self.dns_rules_store]
        if not rules:
            self.dns_log.append_safe("Добавьте хотя бы одно правило (домен + IP)", 'error'); return
        self.dns_running = True
        now = time.time()
        self.dns_stats.update(start_time=now, intercepted=0, spoofed=0,
                              last_update=now, last_spoofed=0)
        args = [self.dns_iface.get_active_text(), self.dns_ttl.get_text(),
                victim, gateway]
        if self.dns_catchall.get_active():
            args.append("--catch-all")
        for d, ip in rules:
            args += [d, ip]
        self.run_binary('DNSspoof', args, self.dns_log, self.dns_status,
                        self.dns_start_btn, self.dns_stop_btn)
        self.start_stats_timer('dns')

    def stop_dns(self, *_):
        self.dns_running = False
        self.stop_binary(self.dns_log, self.dns_status)

    # ================= MAC Flood =================
    def create_mac_tab(self):
        scroll, tab = self._setup_tab()
        g = self._setup_grid(tab)
        self.mac_iface = self.create_iface_combo()
        self.mac_count = self.create_num_entry("0")
        self.mac_threads = self.create_num_entry("1")
        self.mac_mode = Gtk.ComboBoxText()
        for m in ("Flood", "Random", "Sequential"):
            self.mac_mode.append_text(m)
        self.mac_mode.set_active(0)
        self.mac_target_ip = self.create_text_entry("", 15)
        self.mac_target_ip.set_placeholder_text("192.168.1.1")
        for i, (lbl, w) in enumerate((
                ("Интерфейс:", self.mac_iface),
                ("Количество (0=∞):", self.mac_count),
                ("Потоки (threads):", self.mac_threads),
                ("Режим MAC:", self.mac_mode),
                ("Целевой IP (опц.):", self.mac_target_ip))):
            self._row(g, i, lbl, w)

        c, self.mac_start_btn, self.mac_stop_btn = self.create_attack_controls(
            self.start_mac, self.stop_mac)
        tab.pack_start(c, False, False, 0)

        sf, sg = self._stats_frame()
        self.mac_sent_label = self._stat(sg, 0, "Отправлено фреймов:")
        self.mac_rate_label = self._stat(sg, 1, "Скорость (fps):")
        self.mac_time_label = self._stat(sg, 2, "Время работы:")
        self.mac_time_label.set_text("00:00:00")
        tab.pack_start(sf, False, False, 0)

        self.mac_status = self._status_box(tab)
        self.mac_log = LogWidget(200)
        self._finish_tab(scroll, tab, self.mac_log, "MAC Flood")
        self.mac_running = False

    def start_mac(self, *_):
        self.mac_running = True
        now = time.time()
        self.mac_stats.update(start_time=now, sent_frames=0,
                              last_update=now, last_sent=0)
        args = [self.mac_iface.get_active_text(), self.mac_count.get_text(),
                self.mac_threads.get_text(), self.mac_mode.get_active_text().lower()]
        tgt = self.mac_target_ip.get_text().strip()
        if tgt:
            args.append(tgt)
        self.run_binary('MACflood', args, self.mac_log, self.mac_status,
                        self.mac_start_btn, self.mac_stop_btn)
        self.start_stats_timer('mac')

    def stop_mac(self, *_):
        self.mac_running = False
        self.stop_binary(self.mac_log, self.mac_status)

    # ================= Intercept =================
    def create_intercept_tab(self):
        tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        for fn in (tab.set_margin_start, tab.set_margin_end,
                   tab.set_margin_top, tab.set_margin_bottom):
            fn(10)

        pf = Gtk.Frame(label="Параметры захвата")
        pb = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        for fn in (pb.set_margin_start, pb.set_margin_end,
                   pb.set_margin_top, pb.set_margin_bottom):
            fn(5)
        pf.add(pb); tab.pack_start(pf, False, False, 0)

        row = Gtk.Box(spacing=10)
        row.pack_start(Gtk.Label(label="Интерфейс:"), False, False, 0)
        self.intercept_iface = self.create_iface_combo()
        row.pack_start(self.intercept_iface, False, False, 0)
        pb.pack_start(row, False, False, 0)

        tf = Gtk.Frame(label="Типы пакетов для захвата")
        tb = Gtk.Box(spacing=10)
        for fn in (tb.set_margin_start, tb.set_margin_end,
                   tb.set_margin_top, tb.set_margin_bottom):
            fn(5)
        tf.add(tb); pb.pack_start(tf, False, False, 0)

        col1 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        l1 = Gtk.Label(); l1.set_markup("<b>Протоколы</b>"); l1.set_halign(Gtk.Align.START)
        col1.pack_start(l1, False, False, 0)
        self.chk_tcp = Gtk.CheckButton(label="TCP"); self.chk_tcp.set_active(True)
        self.chk_udp = Gtk.CheckButton(label="UDP"); self.chk_udp.set_active(True)
        self.chk_icmp = Gtk.CheckButton(label="ICMP"); self.chk_icmp.set_active(True)
        self.chk_arp = Gtk.CheckButton(label="ARP")
        for c in (self.chk_tcp, self.chk_udp, self.chk_icmp, self.chk_arp):
            col1.pack_start(c, False, False, 0)
        tb.pack_start(col1, True, True, 0)

        col2 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        l2 = Gtk.Label(); l2.set_markup("<b>Популярные порты</b>"); l2.set_halign(Gtk.Align.START)
        col2.pack_start(l2, False, False, 0)
        self.chk_http = Gtk.CheckButton(label="HTTP (80)")
        self.chk_https = Gtk.CheckButton(label="HTTPS (443)")
        self.chk_dns = Gtk.CheckButton(label="DNS (53)")
        self.chk_ssh = Gtk.CheckButton(label="SSH (22)")
        for c in (self.chk_http, self.chk_https, self.chk_dns, self.chk_ssh):
            col2.pack_start(c, False, False, 0)
        tb.pack_start(col2, True, True, 0)

        col3 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        l3 = Gtk.Label(); l3.set_markup("<b>Специальные</b>"); l3.set_halign(Gtk.Align.START)
        col3.pack_start(l3, False, False, 0)
        self.chk_syn = Gtk.CheckButton(label="Только SYN")
        self.chk_resp = Gtk.CheckButton(label="Только ответы")
        self.chk_bcast = Gtk.CheckButton(label="Broadcast")
        for c in (self.chk_syn, self.chk_resp, self.chk_bcast):
            col3.pack_start(c, False, False, 0)
        tb.pack_start(col3, True, True, 0)

        for chk in (self.chk_tcp, self.chk_udp, self.chk_icmp, self.chk_arp,
                    self.chk_http, self.chk_https, self.chk_dns, self.chk_ssh,
                    self.chk_syn, self.chk_resp, self.chk_bcast):
            chk.connect("toggled", self._update_bpf_preview)

        g = Gtk.Grid()
        g.set_column_spacing(10); g.set_row_spacing(5); g.set_halign(Gtk.Align.START)
        g.attach(Gtk.Label(label="Доп. фильтр BPF:"), 0, 0, 1, 1)
        self.intercept_extra = self.create_text_entry("", 30)
        self.intercept_extra.set_placeholder_text("например: host 192.168.1.100")
        g.attach(self.intercept_extra, 1, 0, 1, 1)
        g.attach(Gtk.Label(label="Макс. пакетов (0=∞):"), 0, 1, 1, 1)
        self.intercept_limit_pkts_entry = self.create_num_entry("0")
        g.attach(self.intercept_limit_pkts_entry, 1, 1, 1, 1)
        g.attach(Gtk.Label(label="Макс. ответов (0=∞):"), 0, 2, 1, 1)
        self.intercept_limit_resp_entry = self.create_num_entry("0")
        g.attach(self.intercept_limit_resp_entry, 1, 2, 1, 1)
        pb.pack_start(g, False, False, 0)

        row4 = Gtk.Box(spacing=5)
        row4.pack_start(Gtk.Label(label="Итоговый фильтр:"), False, False, 0)
        self.intercept_bpf_preview = Gtk.Label()
        self.intercept_bpf_preview.set_hexpand(True)
        self.intercept_bpf_preview.set_halign(Gtk.Align.START)
        self.intercept_bpf_preview.set_selectable(True)
        self.intercept_bpf_preview.set_ellipsize(3)
        row4.pack_start(self.intercept_bpf_preview, True, True, 0)
        pb.pack_start(row4, False, False, 0)

        bb = Gtk.Box(spacing=5); bb.set_margin_top(5); bb.set_margin_bottom(5)
        self.intercept_start_btn = Gtk.Button.new_with_label("Начать перехват")
        self.intercept_start_btn.connect("clicked", self.start_sniff)
        self.intercept_stop_btn = Gtk.Button.new_with_label("Остановить")
        self.intercept_stop_btn.connect("clicked", self.stop_sniff)
        self.intercept_stop_btn.set_sensitive(False)
        edit_b = Gtk.Button.new_with_label("Редактировать выбранный")
        edit_b.connect("clicked", self.edit_selected_packet)
        replay_b = Gtk.Button.new_with_label("Повторить выбранный")
        replay_b.connect("clicked", self.replay_selected_packet)
        for b in (self.intercept_start_btn, self.intercept_stop_btn, edit_b, replay_b):
            bb.pack_start(b, False, False, 0)
        tab.pack_start(bb, False, False, 0)

        paned = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        paned.set_vexpand(True)

        tf2 = Gtk.Frame(label="Перехваченные пакеты")
        self.intercept_store = Gtk.ListStore(int, str, str, str, str, object)
        self.intercept_tree = Gtk.TreeView(model=self.intercept_store)
        for i, title in enumerate(("#", "Time", "Source", "Destination", "Protocol")):
            c = Gtk.TreeViewColumn(title, Gtk.CellRendererText(), text=i)
            c.set_resizable(True)
            self.intercept_tree.append_column(c)
        sc = Gtk.ScrolledWindow()
        sc.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        sc.set_min_content_height(150); sc.set_vexpand(True)
        sc.add(self.intercept_tree); tf2.add(sc)
        paned.pack1(tf2, resize=True, shrink=False)

        df = Gtk.Frame(label="Детали пакета")
        self.intercept_details = Gtk.TextView()
        self.intercept_details.set_editable(False)
        self.intercept_details.set_wrap_mode(Gtk.WrapMode.WORD)
        sc2 = Gtk.ScrolledWindow()
        sc2.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        sc2.set_min_content_height(100); sc2.set_vexpand(True)
        sc2.add(self.intercept_details); df.add(sc2)
        paned.pack2(df, resize=True, shrink=False)
        tab.pack_start(paned, True, True, 0)

        self.intercept_status = Gtk.Label(label="Ожидание запуска...")
        self.intercept_status.set_halign(Gtk.Align.START)
        tab.pack_start(self.intercept_status, False, False, 0)

        self.notebook.append_page(tab, Gtk.Label(label="Intercept"))
        self.intercept_tree.get_selection().connect("changed", self.on_packet_selected)
        self._update_bpf_preview(None)

    def _build_bpf_parts(self):
        parts = []
        protos = [n for n, c in (("tcp", self.chk_tcp), ("udp", self.chk_udp),
                                 ("icmp", self.chk_icmp), ("arp", self.chk_arp))
                  if c.get_active()]
        if protos:
            parts.append("(" + " or ".join(protos) + ")")
        ports = [p for p, c in (("port 80", self.chk_http), ("port 443", self.chk_https),
                                ("port 53", self.chk_dns), ("port 22", self.chk_ssh))
                 if c.get_active()]
        if ports:
            parts.append("(" + " or ".join(ports) + ")")
        if self.chk_syn.get_active():
            parts.append("tcp[tcpflags] & (tcp-syn) != 0")
        if self.chk_resp.get_active():
            parts.append("tcp[tcpflags] & (tcp-ack) != 0")
        if self.chk_bcast.get_active():
            parts.append("ether broadcast")
        extra = self.intercept_extra.get_text().strip()
        if extra:
            parts.append("(" + extra + ")")
        return parts

    def _update_bpf_preview(self, _widget):
        parts = self._build_bpf_parts()
        bpf = " and ".join(parts) if parts else "(все пакеты)"
        if hasattr(self, 'intercept_bpf_preview'):
            self.intercept_bpf_preview.set_text(bpf)
            self.intercept_bpf_preview.set_tooltip_text(bpf)

    def packet_callback(self, pkt):
        try:
            limit_pkts = int(self.intercept_limit_pkts_entry.get_text() or 0)
            limit_resp = int(self.intercept_limit_resp_entry.get_text() or 0)
            if limit_pkts > 0 and self.packet_counter >= limit_pkts:
                self.sniff_stop.set(); return
            self.packet_counter += 1
            num = self.packet_counter
            is_resp = (TCP in pkt and pkt[TCP].flags & 0x10) or UDP in pkt or ICMP in pkt
            if is_resp:
                if limit_resp > 0 and self.response_counter >= limit_resp:
                    self.sniff_stop.set(); return
                self.response_counter += 1
            src = dst = prot = "N/A"
            if IP in pkt:
                src, dst = pkt[IP].src, pkt[IP].dst
            elif IPv6 in pkt:
                src, dst = pkt[IPv6].src, pkt[IPv6].dst
            if TCP in pkt:   prot = "TCP"
            elif UDP in pkt: prot = "UDP"
            elif ICMP in pkt: prot = "ICMP"
            elif ARP in pkt:  prot = "ARP"
            elif Ether in pkt: prot = hex(pkt[Ether].type)
            GLib.idle_add(self.update_packet_list, num, pkt.time, src, dst, prot, pkt)
        except Exception as e:
            print(f"Ошибка обработки пакета: {e}")

    def update_packet_list(self, num, time_str, src, dst, prot, pkt):
        self.intercept_store.append([num, str(time_str), src, dst, prot, pkt])
        self.captured_packets.append(pkt)

    def start_sniff(self, *_):
        if self.sniffing_running:
            return
        iface = self.intercept_iface.get_active_text()
        fltr = " and ".join(self._build_bpf_parts())
        self.sniffing_running = True
        self.sniff_stop.clear()
        self.intercept_status.set_text(f"Перехват запущен... Фильтр: {fltr or '(нет)'}")
        self.intercept_start_btn.set_sensitive(False)
        self.intercept_stop_btn.set_sensitive(True)
        self.packet_counter = 0
        self.response_counter = 0
        self.captured_packets = []
        self.intercept_store.clear()

        def worker():
            try:
                sniff(iface=iface, filter=fltr or None, prn=self.packet_callback,
                      store=False, stop_filter=lambda _x: self.sniff_stop.is_set())
            except Exception as e:
                print(f"Ошибка перехвата: {e}")
                GLib.idle_add(self.intercept_status.set_text, f"Ошибка: {e}")
            finally:
                self.sniffing_running = False
                GLib.idle_add(self.intercept_start_btn.set_sensitive, True)
                GLib.idle_add(self.intercept_stop_btn.set_sensitive, False)
                msg = ("Перехват остановлен вручную" if self.sniff_stop.is_set()
                       else "Перехват завершен (лимит)")
                GLib.idle_add(self.intercept_status.set_text, msg)

        self.sniff_thread = threading.Thread(target=worker, daemon=True)
        self.sniff_thread.start()

    def stop_sniff(self, *_):
        if self.sniffing_running:
            self.sniff_stop.set()
            self.intercept_status.set_text("Остановка перехвата...")

    def on_packet_selected(self, selection):
        _, it = selection.get_selected()
        if it:
            pkt = self.intercept_store[it][5]
            if pkt:
                b = self.intercept_details.get_buffer()
                b.set_text(f"=== Summary ===\n{pkt.summary()}\n=== Details ===\n{pkt.show(dump=True)}")

    def edit_selected_packet(self, *_):
        _, it = self.intercept_tree.get_selection().get_selected()
        if it:
            d = PacketEditorDialog(self.root, self.intercept_store[it][5], self.on_packet_edited)
            d.show_all()
        else:
            self.show_warning("Ошибка", "Выберите пакет для редактирования")

    def on_packet_edited(self, edited_pkt, success):
        if success:
            self.edited_packet = edited_pkt
            self.status_var.set_label("Пакет отредактирован, готов к отправке")

    def replay_selected_packet(self, *_):
        pkt = self.edited_packet
        if not pkt:
            _, it = self.intercept_tree.get_selection().get_selected()
            if it:
                pkt = self.intercept_store[it][5]
        if not pkt:
            self.show_warning("Ошибка", "Нет пакета для отправки"); return
        iface = self.intercept_iface.get_active_text()
        try:
            sendp(pkt, iface=iface, verbose=False)
            self.status_var.set_label("Пакет отправлен")
        except Exception as e:
            self.show_warning("Ошибка", f"Не удалось отправить: {e}")

    # ================= Помощь =================
    def create_help_tab(self):
        scroll, tab = self._setup_tab()
        tv = Gtk.TextView()
        tv.set_editable(False)
        tv.set_wrap_mode(Gtk.WrapMode.WORD)
        tv.get_buffer().set_text(
            "Gotcha Linux - Инструментарий для тестирования сетевой безопасности\n\n"
            "Инструкции по использованию:\n\n"
            "- Вкладка 'Доступ': базовые сетевые утилиты (ping, сканирование портов и т.д.)\n"
            "- Вкладка 'Intercept': перехват пакетов с фильтрацией по типам.\n"
            "  * Чекбоксы выбирают типы пакетов, BPF-фильтр собирается автоматически\n"
            "  * '0' в лимитах = бесконечный захват\n"
            "- Вкладка 'DHCP Starvation': исчерпывает IP-адреса DHCP-сервера\n"
            "- Вкладка 'ARP Spoofing': атака типа 'человек посередине'\n"
            "- Вкладка 'DoS атака': генерирует трафик для отказа в обслуживании\n"
            "  * Поле 'Потоки (threads)' задаёт число параллельных отправителей\n"
            "- Вкладка 'DNS Spoofing': ARP + DNS спуфинг\n"
            "- Вкладка 'MAC Flood': заполняет таблицу MAC-адресов коммутатора\n\n"
            "Интерфейс использует глобальную GTK-тему системы.\n"
            "Все атакующие функции требуют прав root (запрашиваются автоматически).\n"
            "Авторские права (c) 2026")
        tab.pack_start(tv, True, True, 0)
        scroll.add(tab)
        self.notebook.append_page(scroll, Gtk.Label(label="Помощь"))

    def on_closing(self, *_):
        self.stop_all()
        Gtk.main_quit()

    def run(self):
        Gtk.main()


if __name__ == '__main__':
    app = GotchaGTK()
    app.run()
