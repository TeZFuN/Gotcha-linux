#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import pwd
import subprocess
import threading
import time
import re
import socket
import signal
import configparser
from datetime import datetime

# ========== ВОССТАНОВЛЕНИЕ HOME ПРИ ЗАПУСКЕ ЧЕРЕЗ sudo/pkexec ==========
# Нужно, чтобы GTK подхватил глобальную тему, иконки и шрифты пользователя,
# а не падал на дефолтную Adwaita (чёрная/белая) из-за HOME=/root
def _restore_user_home():
    if os.geteuid() != 0:
        return
    home = None
    user = os.environ.get("SUDO_USER")
    if user:
        try:
            home = pwd.getpwnam(user).pw_dir
        except KeyError:
            home = None
    else:
        uid = os.environ.get("PKEXEC_UID")
        if uid:
            try:
                home = pwd.getpwuid(int(uid)).pw_dir
            except (KeyError, ValueError):
                home = None
    if home and os.path.isdir(home):
        os.environ["HOME"] = home
        os.environ.setdefault("XDG_CONFIG_HOME", os.path.join(home, ".config"))
        os.environ.setdefault("XDG_DATA_HOME", os.path.join(home, ".local", "share"))
        os.environ.setdefault("XDG_CACHE_HOME", os.path.join(home, ".cache"))

_restore_user_home()  # ДО импорта gi!

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GLib

try:
    from scapy.all import sniff, sendp, Ether, IP, TCP, UDP, ICMP, ARP, Raw, IPv6
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ========== Вспомогательные функции ==========
def get_network_interfaces():
    ifaces = {}
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                ip = addrs[netifaces.AF_INET][0]['addr']
                if ip != '127.0.0.1':
                    ifaces[iface] = ip
        return ifaces
    except ImportError:
        try:
            result = subprocess.run(['ip', '-4', '-o', 'addr', 'show'], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 7:
                    iface = parts[1]
                    ip = parts[3].split('/')[0]
                    if iface != 'lo' and ip != '127.0.0.1':
                        ifaces[iface] = ip
            return ifaces
        except:
            return {'eth0': '192.168.1.x', 'wlan0': '192.168.1.x'}

def is_root():
    return os.geteuid() == 0

def find_exe(exe_name):
    base = os.path.dirname(os.path.abspath(__file__))
    paths = [
        os.path.join(base, "bin", exe_name),
        os.path.join(base, exe_name),
        os.path.join(os.getcwd(), "bin", exe_name),
        os.path.join(os.getcwd(), exe_name),
    ]
    for p in paths:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None

def apply_global_gtk_theme():
    """Применяет глобальную GTK-тему из settings.ini (работает даже под sudo)."""
    settings = Gtk.Settings.get_default()
    if settings is None:
        return
    candidates = []
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        candidates.append(os.path.join(xdg, "gtk-3.0", "settings.ini"))
    candidates.append(os.path.join(os.path.expanduser("~"), ".config", "gtk-3.0", "settings.ini"))
    candidates.append("/etc/gtk-3.0/settings.ini")
    for path in candidates:
        if not os.path.isfile(path):
            continue
        cp = configparser.ConfigParser()
        try:
            cp.read(path)
        except Exception:
            continue
        if not cp.has_section("Settings"):
            continue
        s = cp["Settings"]
        try:
            if s.get("gtk-theme-name"):
                settings.set_property("gtk-theme-name", s["gtk-theme-name"])
            if s.get("gtk-icon-theme-name"):
                settings.set_property("gtk-icon-theme-name", s["gtk-icon-theme-name"])
            if s.get("gtk-font-name"):
                settings.set_property("gtk-font-name", s["gtk-font-name"])
            if s.get("gtk-cursor-theme-name"):
                settings.set_property("gtk-cursor-theme-name", s["gtk-cursor-theme-name"])
            if "gtk-application-prefer-dark-theme" in s:
                settings.set_property("gtk-application-prefer-dark-theme",
                                      s.getboolean("gtk-application-prefer-dark-theme", False))
        except Exception:
            pass
        break

# ========== Класс лога ==========
class LogWidget(Gtk.ScrolledWindow):
    def __init__(self, min_height=200):
        super().__init__()
        self.set_min_content_height(min_height)
        self.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        self.set_vexpand(True)
        self.set_hexpand(True)  # Лог ДОЛЖЕН растягиваться на всю ширину
        self.textview = Gtk.TextView()
        self.textview.set_editable(False)
        self.textview.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.add(self.textview)
        self.buffer = self.textview.get_buffer()
        self.buffer.create_tag('timestamp', foreground='#888888')
        self.buffer.create_tag('log_info', foreground='#60a5fa')
        self.buffer.create_tag('log_success', foreground='#4ade80')
        self.buffer.create_tag('log_warning', foreground='#fbbf24')
        self.buffer.create_tag('log_error', foreground='#ef4444')
        self._scroll_timeout = None

    def append(self, msg, level='info'):
        timestamp = datetime.now().strftime('%H:%M:%S')
        tag = f'log_{level}'
        buffer = self.buffer
        iter_time = buffer.get_end_iter()
        buffer.insert_with_tags_by_name(iter_time, f"[{timestamp}] ", 'timestamp')
        iter_msg = buffer.get_end_iter()
        buffer.insert_with_tags_by_name(iter_msg, msg + '\n', tag)
        self._schedule_scroll()

    def _schedule_scroll(self):
        if self._scroll_timeout is not None:
            GLib.source_remove(self._scroll_timeout)
        self._scroll_timeout = GLib.timeout_add(50, self._do_scroll)

    def _do_scroll(self):
        self._scroll_timeout = None
        allocation = self.get_allocation()
        if allocation.width <= 1 or allocation.height <= 1:
            return False
        buffer = self.buffer
        end_iter = buffer.get_end_iter()
        self.textview.scroll_to_iter(end_iter, 0.0, False, 0, 0)
        return False

    def append_safe(self, msg, level='info'):
        GLib.idle_add(self.append, msg, level)

    def get_buffer(self):
        return self.buffer

# ========== Редактор пакетов ==========
class PacketEditorDialog(Gtk.Dialog):
    def __init__(self, parent, packet, callback):
        super().__init__(title="Редактор пакета", transient_for=parent, modal=True)
        self.set_default_size(800, 700)
        self.packet = packet
        self.callback = callback
        self.edited_packet = None
        self.build_ui()
        self.parse_packet()
        self.show_all()

    def build_ui(self):
        vbox = self.get_content_area()
        vbox.set_spacing(5)
        vbox.set_margin_start(10)
        vbox.set_margin_end(10)
        vbox.set_margin_top(10)
        vbox.set_margin_bottom(10)

        eth_frame = Gtk.Frame(label="Ethernet")
        eth_grid = Gtk.Grid()
        eth_grid.set_column_spacing(5); eth_grid.set_row_spacing(5)
        eth_grid.set_margin_start(5); eth_grid.set_margin_end(5)
        eth_grid.set_margin_top(5); eth_grid.set_margin_bottom(5)
        eth_frame.add(eth_grid)
        eth_grid.attach(Gtk.Label(label="Source MAC:"), 0, 0, 1, 1)
        self.eth_src = Gtk.Entry(); self.eth_src.set_width_chars(17)
        eth_grid.attach(self.eth_src, 1, 0, 1, 1)
        eth_grid.attach(Gtk.Label(label="Dest MAC:"), 0, 1, 1, 1)
        self.eth_dst = Gtk.Entry(); self.eth_dst.set_width_chars(17)
        eth_grid.attach(self.eth_dst, 1, 1, 1, 1)
        vbox.pack_start(eth_frame, False, False, 0)

        ip_frame = Gtk.Frame(label="IP")
        ip_grid = Gtk.Grid()
        ip_grid.set_column_spacing(5); ip_grid.set_row_spacing(5)
        ip_grid.set_margin_start(5); ip_grid.set_margin_end(5)
        ip_grid.set_margin_top(5); ip_grid.set_margin_bottom(5)
        ip_frame.add(ip_grid)
        ip_grid.attach(Gtk.Label(label="Source IP:"), 0, 0, 1, 1)
        self.ip_src = Gtk.Entry(); self.ip_src.set_width_chars(15)
        ip_grid.attach(self.ip_src, 1, 0, 1, 1)
        ip_grid.attach(Gtk.Label(label="Dest IP:"), 0, 1, 1, 1)
        self.ip_dst = Gtk.Entry(); self.ip_dst.set_width_chars(15)
        ip_grid.attach(self.ip_dst, 1, 1, 1, 1)
        ip_grid.attach(Gtk.Label(label="TTL:"), 0, 2, 1, 1)
        self.ip_ttl = Gtk.Entry(); self.ip_ttl.set_width_chars(5)
        ip_grid.attach(self.ip_ttl, 1, 2, 1, 1)
        vbox.pack_start(ip_frame, False, False, 0)

        trans_frame = Gtk.Frame(label="Transport")
        trans_grid = Gtk.Grid()
        trans_grid.set_column_spacing(5); trans_grid.set_row_spacing(5)
        trans_grid.set_margin_start(5); trans_grid.set_margin_end(5)
        trans_grid.set_margin_top(5); trans_grid.set_margin_bottom(5)
        trans_frame.add(trans_grid)
        trans_grid.attach(Gtk.Label(label="Protocol:"), 0, 0, 1, 1)
        self.proto_combo = Gtk.ComboBoxText()
        for p in ["TCP", "UDP", "ICMP", "RAW"]:
            self.proto_combo.append_text(p)
        self.proto_combo.set_active(0)
        trans_grid.attach(self.proto_combo, 1, 0, 1, 1)
        trans_grid.attach(Gtk.Label(label="Source Port:"), 0, 1, 1, 1)
        self.src_port = Gtk.Entry(); self.src_port.set_width_chars(6)
        trans_grid.attach(self.src_port, 1, 1, 1, 1)
        trans_grid.attach(Gtk.Label(label="Dest Port:"), 0, 2, 1, 1)
        self.dst_port = Gtk.Entry(); self.dst_port.set_width_chars(6)
        trans_grid.attach(self.dst_port, 1, 2, 1, 1)
        vbox.pack_start(trans_frame, False, False, 0)

        flags_frame = Gtk.Frame(label="TCP Flags")
        flags_box = Gtk.Box(spacing=5)
        flags_box.set_margin_start(5); flags_box.set_margin_end(5)
        flags_box.set_margin_top(5); flags_box.set_margin_bottom(5)
        self.tcp_flags = {}
        for f in ["FIN","SYN","RST","PSH","ACK","URG","ECE","CWR"]:
            cb = Gtk.CheckButton(label=f)
            flags_box.pack_start(cb, False, False, 0)
            self.tcp_flags[f] = cb
        flags_frame.add(flags_box)
        vbox.pack_start(flags_frame, False, False, 0)

        payload_frame = Gtk.Frame(label="Payload (hex)")
        self.payload_text = Gtk.TextView()
        self.payload_text.set_wrap_mode(Gtk.WrapMode.WORD)
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scrolled.set_min_content_height(150)
        scrolled.set_vexpand(True)
        scrolled.add(self.payload_text)
        payload_frame.add(scrolled)
        vbox.pack_start(payload_frame, True, True, 0)

        btn_box = Gtk.Box(spacing=10)
        btn_box.set_margin_start(10); btn_box.set_margin_end(10)
        btn_box.set_margin_top(10); btn_box.set_margin_bottom(10)
        apply_btn = Gtk.Button.new_with_label("Применить")
        apply_btn.connect("clicked", self.on_apply)
        btn_box.pack_start(apply_btn, False, False, 0)
        cancel_btn = Gtk.Button.new_with_label("Отмена")
        cancel_btn.connect("clicked", lambda w: self.destroy())
        btn_box.pack_start(cancel_btn, False, False, 0)
        vbox.pack_start(btn_box, False, False, 0)

    def parse_packet(self):
        if not SCAPY_AVAILABLE:
            return
        if self.packet.haslayer(Ether):
            self.eth_src.set_text(self.packet[Ether].src)
            self.eth_dst.set_text(self.packet[Ether].dst)
        ip_layer = None
        if self.packet.haslayer(IP):
            ip_layer = self.packet[IP]
        elif self.packet.haslayer(IPv6):
            ip_layer = self.packet[IPv6]
        if ip_layer:
            self.ip_src.set_text(ip_layer.src)
            self.ip_dst.set_text(ip_layer.dst)
            if hasattr(ip_layer, 'ttl'):
                self.ip_ttl.set_text(str(ip_layer.ttl))
            elif hasattr(ip_layer, 'hlim'):
                self.ip_ttl.set_text(str(ip_layer.hlim))
        if self.packet.haslayer(TCP):
            self.proto_combo.set_active(0)
            self.src_port.set_text(str(self.packet[TCP].sport))
            self.dst_port.set_text(str(self.packet[TCP].dport))
            flags = self.packet[TCP].flags
            flag_map = {'FIN':0x01,'SYN':0x02,'RST':0x04,'PSH':0x08,
                        'ACK':0x10,'URG':0x20,'ECE':0x40,'CWR':0x80}
            for f, cb in self.tcp_flags.items():
                cb.set_active(bool(flags & flag_map[f]))
        elif self.packet.haslayer(UDP):
            self.proto_combo.set_active(1)
            self.src_port.set_text(str(self.packet[UDP].sport))
            self.dst_port.set_text(str(self.packet[UDP].dport))
        elif self.packet.haslayer(ICMP):
            self.proto_combo.set_active(2)
        if self.packet.haslayer(Raw):
            self.payload_text.get_buffer().set_text(self.packet[Raw].load.hex(), -1)

    def on_apply(self, widget):
        try:
            self.edited_packet = self.packet
            self.callback(self.edited_packet, True)
            self.destroy()
        except Exception as e:
            dialog = Gtk.MessageDialog(transient_for=self, flags=0,
                                       message_type=Gtk.MessageType.ERROR,
                                       buttons=Gtk.ButtonsType.OK,
                                       text="Ошибка редактирования")
            dialog.format_secondary_text(str(e))
            dialog.run()
            dialog.destroy()

# ========== Основной класс ==========
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
        self.dhcp_stats = {'start_time':0,'sent_packets':0,'unique_macs':0,'last_update':0,'last_sent':0}
        self.dhcp_offered_ips = set()
        self.dhcp_lock = threading.Lock()
        self.arp_stats = {'start_time':0,'sent_packets':0,'last_update':0,'last_sent':0}
        self.dos_stats = {'start_time':0,'sent_packets':0,'last_update':0,'last_sent':0}
        self.dns_stats = {'start_time':0,'intercepted':0,'spoofed':0,'last_update':0,'last_spoofed':0}
        self.mac_stats = {'start_time':0,'sent_frames':0,'last_update':0,'last_sent':0}
        self.stats_timers = {}
        self.build_gui()
        if not is_root():
            self.show_warning("Внимание", "Некоторые функции требуют прав root.\nЗапустите программу с sudo.")
        self.root.connect("destroy", self.on_closing)

    # ===== КОМПАКТНЫЕ ПОЛЯ ВВОДА =====
    def create_num_entry(self, default='0', min_chars=6, max_chars=12):
        """Компактное числовое поле: не растягивается на окно,
        но автоматически растёт, если число не влезает."""
        entry = Gtk.Entry()
        entry.set_text(str(default))
        entry.set_width_chars(min_chars)
        entry.set_max_width_chars(max_chars)
        entry.set_hexpand(False)
        entry.set_halign(Gtk.Align.START)
        def _on_changed(e):
            need = max(min_chars, min(max_chars, len(e.get_text()) + 1))
            if e.get_width_chars() != need:
                e.set_width_chars(need)
        entry.connect("changed", _on_changed)
        return entry

    def create_text_entry(self, default='', chars=15):
        """Компактное текстовое поле (IP, MAC и т.п.) фиксированной ширины."""
        entry = Gtk.Entry()
        entry.set_text(default)
        entry.set_width_chars(chars)
        entry.set_hexpand(False)
        entry.set_halign(Gtk.Align.START)
        return entry

    def build_gui(self):
        apply_global_gtk_theme()  # ✅ Применяем глобальную тему пользователя
        self.root = Gtk.Window(title="Gotcha Linux")
        self.root.set_default_size(1200, 800)
        self.root.set_size_request(800, 600)
        self.root.set_position(Gtk.WindowPosition.CENTER)

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        main_box.set_margin_start(10); main_box.set_margin_end(10)
        main_box.set_margin_top(10); main_box.set_margin_bottom(10)
        self.root.add(main_box)

        header = Gtk.Label()
        header.set_markup("<span size='x-large' weight='bold'>Gotcha Linux</span>")
        main_box.pack_start(header, False, False, 0)

        self.notebook = Gtk.Notebook()
        self.notebook.set_vexpand(True)
        self.notebook.set_hexpand(True)
        main_box.pack_start(self.notebook, True, True, 0)

        self.create_access_tab()
        self.create_intercept_tab()
        self.create_dhcp_tab()
        self.create_arp_tab()
        self.create_dos_tab()
        self.create_dns_tab()
        self.create_mac_tab()
        self.create_help_tab()

        status_box = Gtk.Box(spacing=5)
        status_box.set_margin_top(5)
        main_box.pack_start(status_box, False, False, 0)
        self.status_var = Gtk.Label(label="Готов к работе")
        self.status_var.set_halign(Gtk.Align.START)
        self.status_var.set_valign(Gtk.Align.CENTER)
        self.status_var.set_hexpand(True)
        status_box.pack_start(self.status_var, True, True, 0)
        stop_all_btn = Gtk.Button.new_with_label("Остановить все")
        stop_all_btn.connect("clicked", self.stop_all)
        status_box.pack_start(stop_all_btn, False, False, 0)
        quit_btn = Gtk.Button.new_with_label("Выход")
        quit_btn.connect("clicked", self.on_closing)
        status_box.pack_start(quit_btn, False, False, 0)
        self.root.show_all()

    def show_warning(self, title, msg):
        dialog = Gtk.MessageDialog(transient_for=self.root, flags=0,
                                   message_type=Gtk.MessageType.WARNING,
                                   buttons=Gtk.ButtonsType.OK,
                                   text=title)
        dialog.format_secondary_text(msg)
        dialog.run()
        dialog.destroy()

    def create_iface_combo(self):
        combo = Gtk.ComboBoxText()
        for iface in self.iface_list:
            combo.append_text(iface)
        if self.iface_list:
            combo.set_active(0)
        combo.set_hexpand(False)          # ✅ не растягиваем
        combo.set_halign(Gtk.Align.START)
        return combo

    def create_attack_controls(self, start_cb, stop_cb):
        box = Gtk.Box(spacing=5)
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        start_btn = Gtk.Button.new_with_label("Запустить")
        start_btn.connect("clicked", start_cb)
        box.pack_start(start_btn, False, False, 0)
        stop_btn = Gtk.Button.new_with_label("Остановить")
        stop_btn.connect("clicked", stop_cb)
        stop_btn.set_sensitive(False)
        box.pack_start(stop_btn, False, False, 0)
        return box, start_btn, stop_btn

    def add_save_log_button(self, parent, log_widget):
        btn = Gtk.Button.new_with_label("Сохранить лог")
        btn.connect("clicked", lambda w: self.save_log(log_widget))
        parent.pack_start(btn, False, False, 0)
        return btn

    def save_log(self, log_widget):
        dialog = Gtk.FileChooserDialog(title="Сохранить лог", parent=self.root,
                                       action=Gtk.FileChooserAction.SAVE,
                                       buttons=(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                                                Gtk.STOCK_SAVE, Gtk.ResponseType.OK))
        dialog.set_current_name("log.txt")
        if dialog.run() == Gtk.ResponseType.OK:
            filename = dialog.get_filename()
            if filename:
                try:
                    buffer = log_widget.get_buffer()
                    text = buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), False)
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(text)
                    self.status_var.set_label("Лог сохранён")
                except Exception as e:
                    self.show_warning("Ошибка", f"Не удалось сохранить: {e}")
        dialog.destroy()

    def run_binary(self, bin_name, args, log_widget, status_label, start_btn, stop_btn):
        if self.attack_running:
            return
        bin_path = find_exe(bin_name)
        if not bin_path:
            log_widget.append_safe(f'Ошибка: бинарник {bin_name} не найден', 'error')
            self.show_warning("Ошибка", f"Бинарник {bin_name} не найден.\nПроверьте папку bin/.")
            return
        cmd = [bin_path] + args
        log_widget.append_safe(f'Запуск: {" ".join(cmd)}', 'info')
        self.attack_running = True
        self.stop_event.clear()
        self.current_log = log_widget
        self.current_status = status_label
        status_label.set_label("Запущен...")
        self.status_var.set_label("Атака выполняется...")
        start_btn.set_sensitive(False)
        stop_btn.set_sensitive(True)

        def target():
            try:
                self.current_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    encoding='utf-8',
                    errors='replace',
                    bufsize=1,
                    preexec_fn=os.setsid if os.name != 'nt' else None
                )
                log_widget.append_safe(f'Процесс запущен (PID={self.current_process.pid})', 'success')
                for line in iter(self.current_process.stdout.readline, ''):
                    if self.stop_event.is_set():
                        break
                    if line.strip():
                        log_widget.append_safe(line.rstrip(), 'info')
                        self._parse_stats(line.rstrip())
                self.current_process.stdout.close()
                return_code = self.current_process.wait()
                if self.stop_event.is_set():
                    log_widget.append_safe('Атака остановлена пользователем', 'warning')
                    status_label.set_label("Остановлено")
                else:
                    if return_code == 0:
                        status_label.set_label("Завершено")
                    else:
                        log_widget.append_safe(f'Бинарник завершён с ошибкой (код {return_code})', 'error')
                        status_label.set_label("Ошибка")
            except Exception as e:
                log_widget.append_safe(f'Ошибка: {str(e)}', 'error')
                status_label.set_label("Ошибка")
            finally:
                self.attack_running = False
                self.current_process = None
                self.status_var.set_label("Готов")
                start_btn.set_sensitive(True)
                stop_btn.set_sensitive(False)

        threading.Thread(target=target, daemon=True).start()

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

    def stop_all(self, widget):
        if self.attack_running and self.current_log and self.current_status:
            self.stop_binary(self.current_log, self.current_status)
        if self.sniffing_running:
            self.stop_sniff(None)
        self.status_var.set_label("Остановлено все")

    def _parse_stats(self, line):
        if "[CAPTURED]" in line:
            match = re.search(r"->\s*([\d.]+)", line)
            if match:
                with self.dhcp_lock:
                    self.dhcp_offered_ips.add(match.group(1))
                self._update_dhcp_stats()
        elif "[STATS]" in line:
            sent = re.search(r"Sent:\s*(\d+)", line)
            unique = re.search(r"Unique MACs:\s*(\d+)", line)
            if sent:
                self.dhcp_stats['sent_packets'] = int(sent.group(1))
            if unique:
                self.dhcp_stats['unique_macs'] = int(unique.group(1))
            self._update_dhcp_stats()
        if "Sent Discover" in line:
            self.dhcp_stats['sent_packets'] += 1
            self._update_dhcp_stats()
        if "Sending ARP" in line:
            self.arp_stats['sent_packets'] += 1
            self._update_arp_stats()
        if "Packets:" in line:
            match = re.search(r"Packets:\s*(\d+)", line)
            if match:
                self.dos_stats['sent_packets'] = int(match.group(1))
                self._update_dos_stats()
        if "PPS:" in line:
            match = re.search(r"PPS:\s*([\d.]+)", line)
            if match:
                try:
                    self.dos_rate_label.set_text(str(int(float(match.group(1)))))
                except:
                    pass
        if "DNS Query detected" in line:
            self.dns_stats['intercepted'] += 1
        if "SPOOFING" in line or "CATCH-ALL" in line:
            self.dns_stats['spoofed'] += 1
            self._update_dns_stats()
        if "Sent" in line and "packets" in line:
            match = re.search(r"Sent\s+(\d+)\s+packets", line)
            if match:
                self.mac_stats['sent_frames'] += int(match.group(1))
                self._update_mac_stats()
        if "Flood finished" in line:
            self._update_mac_stats()

    def _fmt_time(self, duration):
        h = int(duration // 3600); m = int((duration % 3600) // 60); s = int(duration % 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    def _update_dhcp_stats(self):
        if not getattr(self, 'dhcp_attack_running', False):
            return
        now = time.time()
        duration = now - self.dhcp_stats['start_time']
        if now - self.dhcp_stats['last_update'] >= 1:
            rate = (self.dhcp_stats['sent_packets'] - self.dhcp_stats.get('last_sent', 0)) / (now - self.dhcp_stats['last_update']) if now - self.dhcp_stats['last_update'] > 0 else 0
            self.dhcp_rate_label.set_text(str(int(rate)))
            self.dhcp_stats['last_update'] = now
            self.dhcp_stats['last_sent'] = self.dhcp_stats['sent_packets']
        self.dhcp_sent_label.set_text(str(self.dhcp_stats['sent_packets']))
        self.dhcp_unique_label.set_text(str(self.dhcp_stats['unique_macs']))
        with self.dhcp_lock:
            self.dhcp_ips_label.set_text(str(len(self.dhcp_offered_ips)))
        self.dhcp_time_label.set_text(self._fmt_time(duration))

    def _update_arp_stats(self):
        if not getattr(self, 'arp_running', False):
            return
        now = time.time()
        duration = now - self.arp_stats['start_time']
        if now - self.arp_stats['last_update'] >= 1:
            rate = (self.arp_stats['sent_packets'] - self.arp_stats.get('last_sent', 0)) / (now - self.arp_stats['last_update']) if now - self.arp_stats['last_update'] > 0 else 0
            self.arp_rate_label.set_text(str(int(rate)))
            self.arp_stats['last_update'] = now
            self.arp_stats['last_sent'] = self.arp_stats['sent_packets']
        self.arp_sent_label.set_text(str(self.arp_stats['sent_packets']))
        self.arp_time_label.set_text(self._fmt_time(duration))

    def _update_dos_stats(self):
        if not getattr(self, 'dos_running', False):
            return
        now = time.time()
        duration = now - self.dos_stats['start_time']
        if now - self.dos_stats['last_update'] >= 1:
            rate = (self.dos_stats['sent_packets'] - self.dos_stats.get('last_sent', 0)) / (now - self.dos_stats['last_update']) if now - self.dos_stats['last_update'] > 0 else 0
            self.dos_rate_label.set_text(str(int(rate)))
            self.dos_stats['last_update'] = now
            self.dos_stats['last_sent'] = self.dos_stats['sent_packets']
        self.dos_sent_label.set_text(str(self.dos_stats['sent_packets']))
        self.dos_time_label.set_text(self._fmt_time(duration))

    def _update_dns_stats(self):
        if not getattr(self, 'dns_running', False):
            return
        now = time.time()
        duration = now - self.dns_stats['start_time']
        if now - self.dns_stats['last_update'] >= 1:
            rate = (self.dns_stats['spoofed'] - self.dns_stats.get('last_spoofed', 0)) / (now - self.dns_stats['last_update']) if now - self.dns_stats['last_update'] > 0 else 0
            self.dns_rate_label.set_text(str(int(rate)))
            self.dns_stats['last_update'] = now
            self.dns_stats['last_spoofed'] = self.dns_stats['spoofed']
        self.dns_intercepted_label.set_text(str(self.dns_stats['intercepted']))
        self.dns_spoofed_label.set_text(str(self.dns_stats['spoofed']))
        self.dns_time_label.set_text(self._fmt_time(duration))

    def _update_mac_stats(self):
        if not getattr(self, 'mac_running', False):
            return
        now = time.time()
        duration = now - self.mac_stats['start_time']
        if now - self.mac_stats['last_update'] >= 1:
            rate = (self.mac_stats['sent_frames'] - self.mac_stats.get('last_sent', 0)) / (now - self.mac_stats['last_update']) if now - self.mac_stats['last_update'] > 0 else 0
            self.mac_rate_label.set_text(str(int(rate)))
            self.mac_stats['last_update'] = now
            self.mac_stats['last_sent'] = self.mac_stats['sent_frames']
        self.mac_sent_label.set_text(str(self.mac_stats['sent_frames']))
        self.mac_time_label.set_text(self._fmt_time(duration))

    def start_stats_timer(self, name):
        if name in self.stats_timers:
            GLib.source_remove(self.stats_timers[name])
        self.stats_timers[name] = GLib.timeout_add_seconds(1, self._update_stats_cb, name)

    def _update_stats_cb(self, name):
        getattr(self, f'_update_{name}_stats')()
        return True

    # ===== Вкладка Доступ =====
    def create_access_tab(self):
        outer_scroll = Gtk.ScrolledWindow()
        outer_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        tab.set_margin_start(10); tab.set_margin_end(10)
        tab.set_margin_top(10); tab.set_margin_bottom(10)

        params = Gtk.Frame(label="Базовые функции доступа")
        grid = Gtk.Grid()
        grid.set_column_spacing(10); grid.set_row_spacing(5)
        grid.set_margin_start(5); grid.set_margin_end(5)
        grid.set_margin_top(5); grid.set_margin_bottom(5)
        grid.set_halign(Gtk.Align.START)   # ✅ компактно, не на всё окно
        params.add(grid)
        grid.attach(Gtk.Label(label="IP адрес:"), 0, 0, 1, 1)
        self.access_ip = self.create_text_entry("192.168.1.1", 15)
        grid.attach(self.access_ip, 1, 0, 1, 1)
        grid.attach(Gtk.Label(label="Интерфейс:"), 0, 1, 1, 1)
        self.access_iface = self.create_iface_combo()
        grid.attach(self.access_iface, 1, 1, 1, 1)
        tab.pack_start(params, False, False, 0)

        # Кнопки в FlowBox — переносятся на новую строку при сужении окна
        btn_flow = Gtk.FlowBox()
        btn_flow.set_valign(Gtk.Align.START)
        btn_flow.set_max_children_per_line(10)
        btn_flow.set_min_children_per_line(2)
        btn_flow.set_selection_mode(Gtk.SelectionMode.NONE)
        btn_flow.set_column_spacing(5)
        btn_flow.set_row_spacing(5)
        for label, cb in [("ICMP Ping", self.on_ping), ("Port Scan", self.on_port_scan),
                          ("Traceroute", self.on_traceroute), ("Таблица маршрутизации", self.on_route),
                          ("Сетевые адаптеры", self.on_adapters), ("Сканировать сеть", self.on_net_scan)]:
            btn = Gtk.Button.new_with_label(label)
            btn.connect("clicked", cb)
            btn_flow.add(btn)
        tab.pack_start(btn_flow, False, False, 0)

        out_frame = Gtk.Frame(label="Результаты")
        out_frame.set_vexpand(True)
        self.access_log = LogWidget(200)
        out_frame.add(self.access_log)
        tab.pack_start(out_frame, True, True, 0)
        self.add_save_log_button(tab, self.access_log)

        outer_scroll.add(tab)
        self.notebook.append_page(outer_scroll, Gtk.Label(label="Доступ"))

    def _run_access_cmd(self, cmd, log_msg):
        if self.access_running:
            self.access_log.append_safe("Операция уже выполняется, подождите...", 'warning')
            return
        self.access_running = True
        self.access_log.append_safe(log_msg, 'info')
        def worker():
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        encoding='utf-8', errors='replace', bufsize=1)
                for line in iter(proc.stdout.readline, ''):
                    if line.strip():
                        self.access_log.append_safe(line.rstrip(), 'info')
                proc.wait()
            except Exception as e:
                self.access_log.append_safe(f"Ошибка: {e}", 'error')
            finally:
                self.access_running = False
        threading.Thread(target=worker, daemon=True).start()

    def on_ping(self, w):
        ip = self.access_ip.get_text().strip()
        if not ip:
            self.access_log.append_safe("Введите IP", 'error')
            return
        self._run_access_cmd(['ping', '-c', '4', ip], f"Ping {ip}...")

    def on_port_scan(self, w):
        ip = self.access_ip.get_text().strip()
        if not ip:
            self.access_log.append_safe("Введите IP", 'error')
            return
        if self.access_running:
            self.access_log.append_safe("Операция уже выполняется, подождите...", 'warning')
            return
        self.access_running = True
        self.access_log.append_safe(f"Port scan {ip}...", 'info')
        def worker():
            ports = [21,22,23,25,53,80,110,143,443,993,995,3389]
            try:
                for p in ports:
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

    def on_traceroute(self, w):
        ip = self.access_ip.get_text().strip()
        if not ip:
            self.access_log.append_safe("Введите IP", 'error')
            return
        self._run_access_cmd(['traceroute', '-n', '-m', '30', '-w', '1', ip], f"Traceroute {ip}...")

    def on_route(self, w):
        self._run_access_cmd(['ip', 'route'], "=== Таблица маршрутизации ===")

    def on_adapters(self, w):
        self._run_access_cmd(['ip', 'addr', 'show'], "=== Сетевые адаптеры ===")

    def on_net_scan(self, w):
        ip = self.access_ip.get_text().strip()
        if not ip:
            self.access_log.append_safe("Введите IP", 'error')
            return
        if self.access_running:
            self.access_log.append_safe("Операция уже выполняется, подождите...", 'warning')
            return
        self.access_running = True
        self.access_log.append_safe(f"Сканирование сети {ip}/24...", 'info')
        def worker():
            try:
                if not SCAPY_AVAILABLE:
                    self.access_log.append_safe("Scapy не установлен", 'error')
                    return
                from scapy.all import ARP, Ether, srp
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip+"/24"), timeout=2, verbose=0)
                self.access_log.append_safe(f"Найдено {len(ans)} хостов:", 'success')
                for _, rcv in ans:
                    self.access_log.append_safe(f"{rcv.psrc}  {rcv.hwsrc}", 'info')
            except Exception as e:
                self.access_log.append_safe(f"Ошибка: {e}", 'error')
            finally:
                self.access_running = False
        threading.Thread(target=worker, daemon=True).start()

    # ===== DHCP Starvation =====
    def create_dhcp_tab(self):
        outer_scroll = Gtk.ScrolledWindow()
        outer_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        tab.set_margin_start(10); tab.set_margin_end(10)
        tab.set_margin_top(10); tab.set_margin_bottom(10)

        grid = Gtk.Grid()
        grid.set_column_spacing(10); grid.set_row_spacing(5)
        grid.set_halign(Gtk.Align.START)
        tab.pack_start(grid, False, False, 0)

        grid.attach(Gtk.Label(label="Интерфейс:"), 0, 0, 1, 1)
        self.dhcp_iface = self.create_iface_combo()
        grid.attach(self.dhcp_iface, 1, 0, 1, 1)
        grid.attach(Gtk.Label(label="Размер пула:"), 0, 1, 1, 1)
        self.dhcp_pool = self.create_num_entry("254")
        grid.attach(self.dhcp_pool, 1, 1, 1, 1)
        grid.attach(Gtk.Label(label="Кол-во запросов:"), 0, 2, 1, 1)
        self.dhcp_count = self.create_num_entry("1000")
        grid.attach(self.dhcp_count, 1, 2, 1, 1)
        grid.attach(Gtk.Label(label="Задержка (сек):"), 0, 3, 1, 1)
        self.dhcp_delay = self.create_num_entry("0.05")
        grid.attach(self.dhcp_delay, 1, 3, 1, 1)
        grid.attach(Gtk.Label(label="Таймаут Offer (сек):"), 0, 4, 1, 1)
        self.dhcp_offer = self.create_num_entry("30")
        grid.attach(self.dhcp_offer, 1, 4, 1, 1)
        grid.attach(Gtk.Label(label="Таймаут ACK (сек):"), 0, 5, 1, 1)
        self.dhcp_ack = self.create_num_entry("5")
        grid.attach(self.dhcp_ack, 1, 5, 1, 1)

        controls, self.dhcp_start_btn, self.dhcp_stop_btn = self.create_attack_controls(self.start_dhcp, self.stop_dhcp)
        tab.pack_start(controls, False, False, 0)

        stats_frame = Gtk.Frame(label="Статистика")
        stats_grid = Gtk.Grid()
        stats_grid.set_column_spacing(10); stats_grid.set_row_spacing(5)
        stats_grid.set_margin_start(5); stats_grid.set_margin_end(5)
        stats_grid.set_margin_top(5); stats_grid.set_margin_bottom(5)
        stats_grid.set_halign(Gtk.Align.START)
        stats_frame.add(stats_grid)
        stats_grid.attach(Gtk.Label(label="Отправлено пакетов:"), 0, 0, 1, 1)
        self.dhcp_sent_label = Gtk.Label(label="0"); stats_grid.attach(self.dhcp_sent_label, 1, 0, 1, 1)
        stats_grid.attach(Gtk.Label(label="Уникальных MAC:"), 0, 1, 1, 1)
        self.dhcp_unique_label = Gtk.Label(label="0"); stats_grid.attach(self.dhcp_unique_label, 1, 1, 1, 1)
        stats_grid.attach(Gtk.Label(label="Захвачено IP:"), 0, 2, 1, 1)
        self.dhcp_ips_label = Gtk.Label(label="0"); stats_grid.attach(self.dhcp_ips_label, 1, 2, 1, 1)
        stats_grid.attach(Gtk.Label(label="Скорость (pps):"), 0, 3, 1, 1)
        self.dhcp_rate_label = Gtk.Label(label="0"); stats_grid.attach(self.dhcp_rate_label, 1, 3, 1, 1)
        stats_grid.attach(Gtk.Label(label="Время работы:"), 0, 4, 1, 1)
        self.dhcp_time_label = Gtk.Label(label="00:00:00"); stats_grid.attach(self.dhcp_time_label, 1, 4, 1, 1)
        tab.pack_start(stats_frame, False, False, 0)

        status_box = Gtk.Box(spacing=5)
        status_box.pack_start(Gtk.Label(label="Статус:"), False, False, 0)
        self.dhcp_status = Gtk.Label(label="Ожидание...")
        status_box.pack_start(self.dhcp_status, False, False, 0)
        tab.pack_start(status_box, False, False, 0)

        self.dhcp_log = LogWidget(200)
        tab.pack_start(self.dhcp_log, True, True, 0)
        self.add_save_log_button(tab, self.dhcp_log)

        outer_scroll.add(tab)
        self.notebook.append_page(outer_scroll, Gtk.Label(label="DHCP Starvation"))
        self.dhcp_attack_running = False

    def start_dhcp(self, w):
        if not is_root():
            self.show_warning("Ошибка", "Запустите программу с sudo.")
            return
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

    def stop_dhcp(self, w):
        self.dhcp_attack_running = False
        self.stop_binary(self.dhcp_log, self.dhcp_status)

    # ===== ARP Spoofing =====
    def create_arp_tab(self):
        outer_scroll = Gtk.ScrolledWindow()
        outer_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        tab.set_margin_start(10); tab.set_margin_end(10)
        tab.set_margin_top(10); tab.set_margin_bottom(10)

        grid = Gtk.Grid()
        grid.set_column_spacing(10); grid.set_row_spacing(5)
        grid.set_halign(Gtk.Align.START)
        tab.pack_start(grid, False, False, 0)
        grid.attach(Gtk.Label(label="Целевой IP:"), 0, 0, 1, 1)
        self.arp_target = self.create_text_entry("192.168.1.100", 15)
        grid.attach(self.arp_target, 1, 0, 1, 1)
        grid.attach(Gtk.Label(label="Шлюз:"), 0, 1, 1, 1)
        self.arp_gateway = self.create_text_entry("192.168.1.1", 15)
        grid.attach(self.arp_gateway, 1, 1, 1, 1)
        grid.attach(Gtk.Label(label="Интерфейс:"), 0, 2, 1, 1)
        self.arp_iface = self.create_iface_combo()
        grid.attach(self.arp_iface, 1, 2, 1, 1)
        grid.attach(Gtk.Label(label="Интервал (сек):"), 0, 3, 1, 1)
        self.arp_interval = self.create_num_entry("2")
        grid.attach(self.arp_interval, 1, 3, 1, 1)

        controls, self.arp_start_btn, self.arp_stop_btn = self.create_attack_controls(self.start_arp, self.stop_arp)
        tab.pack_start(controls, False, False, 0)

        stats_frame = Gtk.Frame(label="Статистика")
        stats_grid = Gtk.Grid()
        stats_grid.set_column_spacing(10); stats_grid.set_row_spacing(5)
        stats_grid.set_margin_start(5); stats_grid.set_margin_end(5)
        stats_grid.set_margin_top(5); stats_grid.set_margin_bottom(5)
        stats_grid.set_halign(Gtk.Align.START)
        stats_frame.add(stats_grid)
        stats_grid.attach(Gtk.Label(label="Отправлено пакетов:"), 0, 0, 1, 1)
        self.arp_sent_label = Gtk.Label(label="0"); stats_grid.attach(self.arp_sent_label, 1, 0, 1, 1)
        stats_grid.attach(Gtk.Label(label="Скорость (pps):"), 0, 1, 1, 1)
        self.arp_rate_label = Gtk.Label(label="0"); stats_grid.attach(self.arp_rate_label, 1, 1, 1, 1)
        stats_grid.attach(Gtk.Label(label="Время работы:"), 0, 2, 1, 1)
        self.arp_time_label = Gtk.Label(label="00:00:00"); stats_grid.attach(self.arp_time_label, 1, 2, 1, 1)
        tab.pack_start(stats_frame, False, False, 0)

        status_box = Gtk.Box(spacing=5)
        status_box.pack_start(Gtk.Label(label="Статус:"), False, False, 0)
        self.arp_status = Gtk.Label(label="Ожидание...")
        status_box.pack_start(self.arp_status, False, False, 0)
        tab.pack_start(status_box, False, False, 0)

        self.arp_log = LogWidget(200)
        tab.pack_start(self.arp_log, True, True, 0)
        self.add_save_log_button(tab, self.arp_log)

        outer_scroll.add(tab)
        self.notebook.append_page(outer_scroll, Gtk.Label(label="ARP Spoofing"))
        self.arp_running = False

    def start_arp(self, w):
        if not is_root():
            self.show_warning("Ошибка", "Запустите программу с sudo.")
            return
        self.arp_running = True
        self.arp_stats['start_time'] = time.time()
        self.arp_stats['sent_packets'] = 0
        args = [self.arp_iface.get_active_text(), self.arp_target.get_text(),
                self.arp_gateway.get_text(), self.arp_interval.get_text()]
        self.run_binary('ARPspoof', args, self.arp_log, self.arp_status,
                        self.arp_start_btn, self.arp_stop_btn)
        self.start_stats_timer('arp')

    def stop_arp(self, w):
        self.arp_running = False
        self.stop_binary(self.arp_log, self.arp_status)

    # ===== DoS атака =====
    def create_dos_tab(self):
        outer_scroll = Gtk.ScrolledWindow()
        outer_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        tab.set_margin_start(10); tab.set_margin_end(10)
        tab.set_margin_top(10); tab.set_margin_bottom(10)

        grid = Gtk.Grid()
        grid.set_column_spacing(10); grid.set_row_spacing(5)
        grid.set_halign(Gtk.Align.START)
        tab.pack_start(grid, False, False, 0)
        grid.attach(Gtk.Label(label="IP адрес:"), 0, 0, 1, 1)
        self.dos_ip = self.create_text_entry("192.168.1.1", 15)
        grid.attach(self.dos_ip, 1, 0, 1, 1)
        grid.attach(Gtk.Label(label="Протокол:"), 0, 1, 1, 1)
        self.dos_proto = Gtk.ComboBoxText()
        for p in ["TCP","UDP","ICMP","ARP"]: self.dos_proto.append_text(p)
        self.dos_proto.set_active(0)
        grid.attach(self.dos_proto, 1, 1, 1, 1)
        grid.attach(Gtk.Label(label="Порт:"), 0, 2, 1, 1)
        self.dos_port = self.create_num_entry("80")
        grid.attach(self.dos_port, 1, 2, 1, 1)
        grid.attach(Gtk.Label(label="Размер пакета:"), 0, 3, 1, 1)
        self.dos_size = self.create_num_entry("1024")
        grid.attach(self.dos_size, 1, 3, 1, 1)
        grid.attach(Gtk.Label(label="MAC назначения:"), 0, 4, 1, 1)
        self.dos_mac = self.create_text_entry("ff:ff:ff:ff:ff:ff", 17)
        grid.attach(self.dos_mac, 1, 4, 1, 1)
        grid.attach(Gtk.Label(label="Время (сек):"), 0, 5, 1, 1)
        self.dos_duration = self.create_num_entry("60")
        grid.attach(self.dos_duration, 1, 5, 1, 1)
        grid.attach(Gtk.Label(label="Интерфейс:"), 0, 6, 1, 1)
        self.dos_iface = self.create_iface_combo()
        grid.attach(self.dos_iface, 1, 6, 1, 1)

        checks_box = Gtk.Box(spacing=10)
        self.dos_random_ip = Gtk.CheckButton(label="Случайный IP")
        self.dos_random_mac = Gtk.CheckButton(label="Случайный MAC")
        checks_box.pack_start(self.dos_random_ip, False, False, 0)
        checks_box.pack_start(self.dos_random_mac, False, False, 0)
        grid.attach(checks_box, 0, 7, 2, 1)

        controls, self.dos_start_btn, self.dos_stop_btn = self.create_attack_controls(self.start_dos, self.stop_dos)
        tab.pack_start(controls, False, False, 0)

        stats_frame = Gtk.Frame(label="Статистика")
        stats_grid = Gtk.Grid()
        stats_grid.set_column_spacing(10); stats_grid.set_row_spacing(5)
        stats_grid.set_margin_start(5); stats_grid.set_margin_end(5)
        stats_grid.set_margin_top(5); stats_grid.set_margin_bottom(5)
        stats_grid.set_halign(Gtk.Align.START)
        stats_frame.add(stats_grid)
        stats_grid.attach(Gtk.Label(label="Отправлено пакетов:"), 0, 0, 1, 1)
        self.dos_sent_label = Gtk.Label(label="0"); stats_grid.attach(self.dos_sent_label, 1, 0, 1, 1)
        stats_grid.attach(Gtk.Label(label="Скорость (pps):"), 0, 1, 1, 1)
        self.dos_rate_label = Gtk.Label(label="0"); stats_grid.attach(self.dos_rate_label, 1, 1, 1, 1)
        stats_grid.attach(Gtk.Label(label="Время работы:"), 0, 2, 1, 1)
        self.dos_time_label = Gtk.Label(label="00:00:00"); stats_grid.attach(self.dos_time_label, 1, 2, 1, 1)
        tab.pack_start(stats_frame, False, False, 0)

        status_box = Gtk.Box(spacing=5)
        status_box.pack_start(Gtk.Label(label="Статус:"), False, False, 0)
        self.dos_status = Gtk.Label(label="Ожидание...")
        status_box.pack_start(self.dos_status, False, False, 0)
        tab.pack_start(status_box, False, False, 0)

        self.dos_log = LogWidget(200)
        tab.pack_start(self.dos_log, True, True, 0)
        self.add_save_log_button(tab, self.dos_log)

        outer_scroll.add(tab)
        self.notebook.append_page(outer_scroll, Gtk.Label(label="DoS атака"))
        self.dos_running = False

    def start_dos(self, w):
        if not is_root():
            self.show_warning("Ошибка", "Запустите программу с sudo.")
            return
        self.dos_running = True
        self.dos_stats['start_time'] = time.time()
        self.dos_stats['sent_packets'] = 0
        proto = self.dos_proto.get_active_text().lower()
        bin_map = {'tcp':'NPtcpT','udp':'NPudpT','icmp':'NPicmpT','arp':'NParpT'}
        bin_name = bin_map.get(proto)
        if not bin_name:
            self.dos_log.append_safe('Неизвестный протокол', 'error')
            return
        iface = self.dos_iface.get_active_text()
        src_ip = self.interfaces.get(iface, '192.168.1.x')
        args = [src_ip, self.dos_ip.get_text(), self.dos_port.get_text(), '4', self.dos_duration.get_text()]
        if self.dos_random_ip.get_active():
            args.append('--random-ip')
        if self.dos_random_mac.get_active():
            args.append('--random-mac')
        args.append('--packet-size')
        args.append(self.dos_size.get_text())
        if self.dos_mac.get_text() != 'ff:ff:ff:ff:ff:ff':
            args.append(self.dos_mac.get_text())
        self.run_binary(bin_name, args, self.dos_log, self.dos_status,
                        self.dos_start_btn, self.dos_stop_btn)
        self.start_stats_timer('dos')

    def stop_dos(self, w):
        self.dos_running = False
        self.stop_binary(self.dos_log, self.dos_status)

    # ===== DNS Spoofing =====
    def create_dns_tab(self):
        outer_scroll = Gtk.ScrolledWindow()
        outer_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        tab.set_margin_start(10); tab.set_margin_end(10)
        tab.set_margin_top(10); tab.set_margin_bottom(10)

        grid = Gtk.Grid()
        grid.set_column_spacing(10); grid.set_row_spacing(5)
        grid.set_halign(Gtk.Align.START)
        tab.pack_start(grid, False, False, 0)
        grid.attach(Gtk.Label(label="Интерфейс:"), 0, 0, 1, 1)
        self.dns_iface = self.create_iface_combo()
        grid.attach(self.dns_iface, 1, 0, 1, 1)
        grid.attach(Gtk.Label(label="TTL (сек):"), 0, 1, 1, 1)
        self.dns_ttl = self.create_num_entry("5")
        grid.attach(self.dns_ttl, 1, 1, 1, 1)
        grid.attach(Gtk.Label(label="IP жертвы:"), 0, 2, 1, 1)
        self.dns_victim_ip = self.create_text_entry("192.168.0.191", 15)
        grid.attach(self.dns_victim_ip, 1, 2, 1, 1)
        grid.attach(Gtk.Label(label="IP шлюза:"), 0, 3, 1, 1)
        self.dns_gateway_ip = self.create_text_entry("192.168.0.1", 15)
        grid.attach(self.dns_gateway_ip, 1, 3, 1, 1)
        self.dns_catchall = Gtk.CheckButton(label="Подменять все запросы (catch-all)")
        grid.attach(self.dns_catchall, 0, 4, 2, 1)

        controls, self.dns_start_btn, self.dns_stop_btn = self.create_attack_controls(self.start_dns, self.stop_dns)
        tab.pack_start(controls, False, False, 0)

        rules_frame = Gtk.Frame(label="Правила подмены (домен → IP)")
        rules_grid = Gtk.Grid()
        rules_grid.set_column_spacing(10); rules_grid.set_row_spacing(5)
        rules_grid.set_margin_start(5); rules_grid.set_margin_end(5)
        rules_grid.set_margin_top(5); rules_grid.set_margin_bottom(5)
        rules_grid.set_halign(Gtk.Align.START)
        rules_frame.add(rules_grid)
        rules_grid.attach(Gtk.Label(label="Домен:"), 0, 0, 1, 1)
        self.dns_domain_entry = self.create_text_entry("", 20)
        rules_grid.attach(self.dns_domain_entry, 1, 0, 1, 1)
        rules_grid.attach(Gtk.Label(label="IP:"), 0, 1, 1, 1)
        self.dns_ip_entry = self.create_text_entry("", 15)
        rules_grid.attach(self.dns_ip_entry, 1, 1, 1, 1)

        btns_box = Gtk.Box(spacing=5)
        add_rule = Gtk.Button.new_with_label("Добавить")
        add_rule.connect("clicked", self.add_dns_rule)
        btns_box.pack_start(add_rule, False, False, 0)
        del_rule = Gtk.Button.new_with_label("Удалить")
        del_rule.connect("clicked", self.del_dns_rule)
        btns_box.pack_start(del_rule, False, False, 0)
        rules_grid.attach(btns_box, 0, 2, 2, 1)

        self.dns_rules_store = Gtk.ListStore(str, str)
        self.dns_rules_tree = Gtk.TreeView(model=self.dns_rules_store)
        self.dns_rules_tree.set_headers_visible(True)
        col_dom = Gtk.TreeViewColumn("Домен (маска *)", Gtk.CellRendererText(), text=0)
        col_ip = Gtk.TreeViewColumn("IP адрес", Gtk.CellRendererText(), text=1)
        self.dns_rules_tree.append_column(col_dom)
        self.dns_rules_tree.append_column(col_ip)
        scrolled_rules = Gtk.ScrolledWindow()
        scrolled_rules.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scrolled_rules.set_min_content_height(100)
        scrolled_rules.add(self.dns_rules_tree)
        rules_grid.attach(scrolled_rules, 0, 3, 2, 1)
        tab.pack_start(rules_frame, False, False, 0)

        stats_frame = Gtk.Frame(label="Статистика")
        stats_grid = Gtk.Grid()
        stats_grid.set_column_spacing(10); stats_grid.set_row_spacing(5)
        stats_grid.set_margin_start(5); stats_grid.set_margin_end(5)
        stats_grid.set_margin_top(5); stats_grid.set_margin_bottom(5)
        stats_grid.set_halign(Gtk.Align.START)
        stats_frame.add(stats_grid)
        stats_grid.attach(Gtk.Label(label="Перехвачено:"), 0, 0, 1, 1)
        self.dns_intercepted_label = Gtk.Label(label="0"); stats_grid.attach(self.dns_intercepted_label, 1, 0, 1, 1)
        stats_grid.attach(Gtk.Label(label="Подменено:"), 0, 1, 1, 1)
        self.dns_spoofed_label = Gtk.Label(label="0"); stats_grid.attach(self.dns_spoofed_label, 1, 1, 1, 1)
        stats_grid.attach(Gtk.Label(label="Скорость (spoof/s):"), 0, 2, 1, 1)
        self.dns_rate_label = Gtk.Label(label="0"); stats_grid.attach(self.dns_rate_label, 1, 2, 1, 1)
        stats_grid.attach(Gtk.Label(label="Время работы:"), 0, 3, 1, 1)
        self.dns_time_label = Gtk.Label(label="00:00:00"); stats_grid.attach(self.dns_time_label, 1, 3, 1, 1)
        tab.pack_start(stats_frame, False, False, 0)

        status_box = Gtk.Box(spacing=5)
        status_box.pack_start(Gtk.Label(label="Статус:"), False, False, 0)
        self.dns_status = Gtk.Label(label="Ожидание...")
        status_box.pack_start(self.dns_status, False, False, 0)
        tab.pack_start(status_box, False, False, 0)

        self.dns_log = LogWidget(200)
        tab.pack_start(self.dns_log, True, True, 0)
        self.add_save_log_button(tab, self.dns_log)

        outer_scroll.add(tab)
        self.notebook.append_page(outer_scroll, Gtk.Label(label="DNS Spoofing"))
        self.dns_running = False

    def add_dns_rule(self, w):
        domain = self.dns_domain_entry.get_text().strip()
        ip = self.dns_ip_entry.get_text().strip()
        if not domain or not ip:
            self.dns_log.append_safe("Введите домен и IP", 'error')
            return
        domain_clean = domain.replace("*.", "").strip(".")
        self.dns_rules_store.append([domain_clean, ip])
        self.dns_domain_entry.set_text("")
        self.dns_ip_entry.set_text("")
        self.dns_log.append_safe(f"Правило добавлено: {domain_clean} -> {ip}", 'success')

    def del_dns_rule(self, w):
        selection = self.dns_rules_tree.get_selection()
        model, treeiter = selection.get_selected()
        if treeiter:
            domain = model[treeiter][0]
            model.remove(treeiter)
            self.dns_log.append_safe(f"Правило удалено: {domain}", 'warning')
        else:
            self.dns_log.append_safe("Выберите правило для удаления", 'warning')

    def start_dns(self, w):
        if not is_root():
            self.show_warning("Ошибка", "Запустите программу с sudo.")
            return
        if self.dns_running:
            self.dns_log.append_safe("DNS Spoofing уже запущен", 'warning')
            return
        victim_ip = self.dns_victim_ip.get_text().strip()
        gateway_ip = self.dns_gateway_ip.get_text().strip()
        if not victim_ip or not gateway_ip:
            self.dns_log.append_safe("Укажите IP жертвы и IP шлюза", 'error')
            return
        rules = []
        for row in self.dns_rules_store:
            rules.append((row[0], row[1]))
        if not rules:
            self.dns_log.append_safe("Добавьте хотя бы одно правило (домен + IP)", 'error')
            return
        self.dns_running = True
        self.dns_stats['start_time'] = time.time()
        self.dns_stats['intercepted'] = 0
        self.dns_stats['spoofed'] = 0
        self.dns_stats['last_update'] = time.time()
        self.dns_stats['last_spoofed'] = 0
        args = [self.dns_iface.get_active_text(), self.dns_ttl.get_text(),
                victim_ip, gateway_ip]
        if self.dns_catchall.get_active():
            args.append("--catch-all")
        for domain, ip in rules:
            args.append(domain)
            args.append(ip)
        self.run_binary('DNSspoof', args, self.dns_log, self.dns_status,
                        self.dns_start_btn, self.dns_stop_btn)
        self.start_stats_timer('dns')

    def stop_dns(self, w):
        self.dns_running = False
        self.stop_binary(self.dns_log, self.dns_status)

    # ===== MAC Flood =====
    def create_mac_tab(self):
        outer_scroll = Gtk.ScrolledWindow()
        outer_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        tab.set_margin_start(10); tab.set_margin_end(10)
        tab.set_margin_top(10); tab.set_margin_bottom(10)

        grid = Gtk.Grid()
        grid.set_column_spacing(10); grid.set_row_spacing(5)
        grid.set_halign(Gtk.Align.START)
        tab.pack_start(grid, False, False, 0)

        grid.attach(Gtk.Label(label="Интерфейс:"), 0, 0, 1, 1)
        self.mac_iface = self.create_iface_combo()
        grid.attach(self.mac_iface, 1, 0, 1, 1)

        grid.attach(Gtk.Label(label="Количество (0=∞):"), 0, 1, 1, 1)
        self.mac_count = self.create_num_entry("0")
        grid.attach(self.mac_count, 1, 1, 1, 1)

        grid.attach(Gtk.Label(label="Потоки (threads):"), 0, 2, 1, 1)
        self.mac_threads = self.create_num_entry("1")
        grid.attach(self.mac_threads, 1, 2, 1, 1)

        grid.attach(Gtk.Label(label="Режим MAC:"), 0, 3, 1, 1)
        self.mac_mode = Gtk.ComboBoxText()
        for m in ["Flood", "Random", "Sequential"]: self.mac_mode.append_text(m)
        self.mac_mode.set_active(0)
        grid.attach(self.mac_mode, 1, 3, 1, 1)

        grid.attach(Gtk.Label(label="Целевой IP (опц.):"), 0, 4, 1, 1)
        self.mac_target_ip = self.create_text_entry("", 15)
        self.mac_target_ip.set_placeholder_text("192.168.1.1")
        grid.attach(self.mac_target_ip, 1, 4, 1, 1)

        controls, self.mac_start_btn, self.mac_stop_btn = self.create_attack_controls(self.start_mac, self.stop_mac)
        tab.pack_start(controls, False, False, 0)

        stats_frame = Gtk.Frame(label="Статистика")
        stats_grid = Gtk.Grid()
        stats_grid.set_column_spacing(10); stats_grid.set_row_spacing(5)
        stats_grid.set_margin_start(5); stats_grid.set_margin_end(5)
        stats_grid.set_margin_top(5); stats_grid.set_margin_bottom(5)
        stats_grid.set_halign(Gtk.Align.START)
        stats_frame.add(stats_grid)
        stats_grid.attach(Gtk.Label(label="Отправлено фреймов:"), 0, 0, 1, 1)
        self.mac_sent_label = Gtk.Label(label="0"); stats_grid.attach(self.mac_sent_label, 1, 0, 1, 1)
        stats_grid.attach(Gtk.Label(label="Скорость (fps):"), 0, 1, 1, 1)
        self.mac_rate_label = Gtk.Label(label="0"); stats_grid.attach(self.mac_rate_label, 1, 1, 1, 1)
        stats_grid.attach(Gtk.Label(label="Время работы:"), 0, 2, 1, 1)
        self.mac_time_label = Gtk.Label(label="00:00:00"); stats_grid.attach(self.mac_time_label, 1, 2, 1, 1)
        tab.pack_start(stats_frame, False, False, 0)

        status_box = Gtk.Box(spacing=5)
        status_box.pack_start(Gtk.Label(label="Статус:"), False, False, 0)
        self.mac_status = Gtk.Label(label="Ожидание...")
        status_box.pack_start(self.mac_status, False, False, 0)
        tab.pack_start(status_box, False, False, 0)

        self.mac_log = LogWidget(200)
        tab.pack_start(self.mac_log, True, True, 0)
        self.add_save_log_button(tab, self.mac_log)

        outer_scroll.add(tab)
        self.notebook.append_page(outer_scroll, Gtk.Label(label="MAC Flood"))
        self.mac_running = False

    def start_mac(self, w):
        if not is_root():
            self.show_warning("Ошибка", "Запустите программу с sudo.")
            return
        self.mac_running = True
        self.mac_stats['start_time'] = time.time()
        self.mac_stats['sent_frames'] = 0
        self.mac_stats['last_update'] = time.time()
        self.mac_stats['last_sent'] = 0

        args = [
            self.mac_iface.get_active_text(),
            self.mac_count.get_text(),
            self.mac_threads.get_text(),
            self.mac_mode.get_active_text().lower()
        ]
        target_ip = self.mac_target_ip.get_text().strip()
        if target_ip:
            args.append(target_ip)

        self.run_binary('MACflood', args, self.mac_log, self.mac_status,
                        self.mac_start_btn, self.mac_stop_btn)
        self.start_stats_timer('mac')

    def stop_mac(self, w):
        self.mac_running = False
        self.stop_binary(self.mac_log, self.mac_status)

    # ===== Intercept =====
    def create_intercept_tab(self):
        tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        tab.set_margin_start(10); tab.set_margin_end(10)
        tab.set_margin_top(10); tab.set_margin_bottom(10)

        params_frame = Gtk.Frame(label="Параметры захвата")
        params_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        params_box.set_margin_start(5); params_box.set_margin_end(5)
        params_box.set_margin_top(5); params_box.set_margin_bottom(5)
        params_frame.add(params_box)

        row1 = Gtk.Box(spacing=10)
        row1.pack_start(Gtk.Label(label="Интерфейс:"), False, False, 0)
        self.intercept_iface = self.create_iface_combo()
        row1.pack_start(self.intercept_iface, False, False, 0)
        params_box.pack_start(row1, False, False, 0)

        types_frame = Gtk.Frame(label="Типы пакетов для захвата")
        types_box = Gtk.Box(spacing=10)
        types_box.set_margin_start(5); types_box.set_margin_end(5)
        types_box.set_margin_top(5); types_box.set_margin_bottom(5)
        types_frame.add(types_box)

        col1 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        lbl1 = Gtk.Label(label="Протоколы"); lbl1.set_markup("<b>Протоколы</b>"); lbl1.set_halign(Gtk.Align.START)
        col1.pack_start(lbl1, False, False, 0)
        self.chk_tcp = Gtk.CheckButton(label="TCP"); self.chk_tcp.set_active(True)
        self.chk_udp = Gtk.CheckButton(label="UDP"); self.chk_udp.set_active(True)
        self.chk_icmp = Gtk.CheckButton(label="ICMP"); self.chk_icmp.set_active(True)
        self.chk_arp = Gtk.CheckButton(label="ARP"); self.chk_arp.set_active(False)
        for c in [self.chk_tcp, self.chk_udp, self.chk_icmp, self.chk_arp]:
            col1.pack_start(c, False, False, 0)
        types_box.pack_start(col1, True, True, 0)

        col2 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        lbl2 = Gtk.Label(); lbl2.set_markup("<b>Популярные порты</b>"); lbl2.set_halign(Gtk.Align.START)
        col2.pack_start(lbl2, False, False, 0)
        self.chk_http = Gtk.CheckButton(label="HTTP (80)")
        self.chk_https = Gtk.CheckButton(label="HTTPS (443)")
        self.chk_dns = Gtk.CheckButton(label="DNS (53)")
        self.chk_ssh = Gtk.CheckButton(label="SSH (22)")
        for c in [self.chk_http, self.chk_https, self.chk_dns, self.chk_ssh]:
            col2.pack_start(c, False, False, 0)
        types_box.pack_start(col2, True, True, 0)

        col3 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        lbl3 = Gtk.Label(); lbl3.set_markup("<b>Специальные</b>"); lbl3.set_halign(Gtk.Align.START)
        col3.pack_start(lbl3, False, False, 0)
        self.chk_syn = Gtk.CheckButton(label="Только SYN")
        self.chk_resp = Gtk.CheckButton(label="Только ответы")
        self.chk_bcast = Gtk.CheckButton(label="Broadcast")
        for c in [self.chk_syn, self.chk_resp, self.chk_bcast]:
            col3.pack_start(c, False, False, 0)
        types_box.pack_start(col3, True, True, 0)

        params_box.pack_start(types_frame, False, False, 0)

        for chk in [self.chk_tcp, self.chk_udp, self.chk_icmp, self.chk_arp,
                    self.chk_http, self.chk_https, self.chk_dns, self.chk_ssh,
                    self.chk_syn, self.chk_resp, self.chk_bcast]:
            chk.connect("toggled", self._update_bpf_preview)

        row3 = Gtk.Grid()
        row3.set_column_spacing(10); row3.set_row_spacing(5)
        row3.set_halign(Gtk.Align.START)
        row3.attach(Gtk.Label(label="Доп. фильтр BPF:"), 0, 0, 1, 1)
        self.intercept_extra = self.create_text_entry("", 30)
        self.intercept_extra.set_placeholder_text("например: host 192.168.1.100")
        row3.attach(self.intercept_extra, 1, 0, 1, 1)
        row3.attach(Gtk.Label(label="Макс. пакетов (0=∞):"), 0, 1, 1, 1)
        self.intercept_limit_pkts_entry = self.create_num_entry("0")
        row3.attach(self.intercept_limit_pkts_entry, 1, 1, 1, 1)
        row3.attach(Gtk.Label(label="Макс. ответов (0=∞):"), 0, 2, 1, 1)
        self.intercept_limit_resp_entry = self.create_num_entry("0")
        row3.attach(self.intercept_limit_resp_entry, 1, 2, 1, 1)
        params_box.pack_start(row3, False, False, 0)

        row4 = Gtk.Box(spacing=5)
        row4.pack_start(Gtk.Label(label="Итоговый фильтр:"), False, False, 0)
        self.intercept_bpf_preview = Gtk.Label()
        self.intercept_bpf_preview.set_hexpand(True)
        self.intercept_bpf_preview.set_halign(Gtk.Align.START)
        self.intercept_bpf_preview.set_selectable(True)
        self.intercept_bpf_preview.set_ellipsize(3)
        row4.pack_start(self.intercept_bpf_preview, True, True, 0)
        params_box.pack_start(row4, False, False, 0)

        tab.pack_start(params_frame, False, False, 0)

        btn_box = Gtk.Box(spacing=5)
        btn_box.set_margin_top(5); btn_box.set_margin_bottom(5)
        start_int = Gtk.Button.new_with_label("Начать перехват")
        start_int.connect("clicked", self.start_sniff)
        btn_box.pack_start(start_int, False, False, 0)
        stop_int = Gtk.Button.new_with_label("Остановить")
        stop_int.connect("clicked", self.stop_sniff)
        stop_int.set_sensitive(False)
        btn_box.pack_start(stop_int, False, False, 0)
        edit_pkt = Gtk.Button.new_with_label("Редактировать выбранный")
        edit_pkt.connect("clicked", self.edit_selected_packet)
        btn_box.pack_start(edit_pkt, False, False, 0)
        replay_pkt = Gtk.Button.new_with_label("Повторить выбранный")
        replay_pkt.connect("clicked", self.replay_selected_packet)
        btn_box.pack_start(replay_pkt, False, False, 0)
        tab.pack_start(btn_box, False, False, 0)

        paned = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        paned.set_vexpand(True)

        tree_frame = Gtk.Frame(label="Перехваченные пакеты")
        self.intercept_store = Gtk.ListStore(int, str, str, str, str, object)
        self.intercept_tree = Gtk.TreeView(model=self.intercept_store)
        for i, title in enumerate(["#", "Time", "Source", "Destination", "Protocol"]):
            col = Gtk.TreeViewColumn(title, Gtk.CellRendererText(), text=i)
            col.set_resizable(True)
            self.intercept_tree.append_column(col)
        tree_scrolled = Gtk.ScrolledWindow()
        tree_scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        tree_scrolled.set_min_content_height(150)
        tree_scrolled.set_vexpand(True)
        tree_scrolled.add(self.intercept_tree)
        tree_frame.add(tree_scrolled)
        paned.pack1(tree_frame, resize=True, shrink=False)

        details_frame = Gtk.Frame(label="Детали пакета")
        self.intercept_details = Gtk.TextView()
        self.intercept_details.set_editable(False)
        self.intercept_details.set_wrap_mode(Gtk.WrapMode.WORD)
        details_scrolled = Gtk.ScrolledWindow()
        details_scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        details_scrolled.set_min_content_height(100)
        details_scrolled.set_vexpand(True)
        details_scrolled.add(self.intercept_details)
        details_frame.add(details_scrolled)
        paned.pack2(details_frame, resize=True, shrink=False)

        tab.pack_start(paned, True, True, 0)

        self.intercept_status = Gtk.Label(label="Ожидание запуска...")
        self.intercept_status.set_halign(Gtk.Align.START)
        tab.pack_start(self.intercept_status, False, False, 0)

        self.notebook.append_page(tab, Gtk.Label(label="Intercept"))
        self.intercept_start_btn = start_int
        self.intercept_stop_btn = stop_int
        self.intercept_tree.get_selection().connect("changed", self.on_packet_selected)
        self._update_bpf_preview(None)

    def _build_bpf_parts(self):
        parts = []
        protos = []
        if self.chk_tcp.get_active(): protos.append("tcp")
        if self.chk_udp.get_active(): protos.append("udp")
        if self.chk_icmp.get_active(): protos.append("icmp")
        if self.chk_arp.get_active(): protos.append("arp")
        if protos:
            parts.append("(" + " or ".join(protos) + ")")
        ports = []
        if self.chk_http.get_active(): ports.append("port 80")
        if self.chk_https.get_active(): ports.append("port 443")
        if self.chk_dns.get_active(): ports.append("port 53")
        if self.chk_ssh.get_active(): ports.append("port 22")
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

    def _update_bpf_preview(self, widget):
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
                self.sniff_stop.set()
                return
            self.packet_counter += 1
            num = self.packet_counter
            is_response = False
            if TCP in pkt and pkt[TCP].flags & 0x10:
                is_response = True
            elif UDP in pkt or ICMP in pkt:
                is_response = True
            if is_response:
                if limit_resp > 0 and self.response_counter >= limit_resp:
                    self.sniff_stop.set()
                    return
                self.response_counter += 1
            time_str = pkt.time
            src = dst = prot = "N/A"
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
            elif IPv6 in pkt:
                src = pkt[IPv6].src
                dst = pkt[IPv6].dst
            if TCP in pkt:
                prot = "TCP"
            elif UDP in pkt:
                prot = "UDP"
            elif ICMP in pkt:
                prot = "ICMP"
            elif ARP in pkt:
                prot = "ARP"
            else:
                if Ether in pkt:
                    prot = hex(pkt[Ether].type)
            GLib.idle_add(self.update_packet_list, num, time_str, src, dst, prot, pkt)
        except Exception as e:
            print(f"Ошибка обработки пакета: {e}")

    def update_packet_list(self, num, time_str, src, dst, prot, pkt):
        self.intercept_store.append([num, str(time_str), src, dst, prot, pkt])
        self.captured_packets.append(pkt)

    def start_sniff(self, w):
        if not is_root():
            self.show_warning("Ошибка", "Запустите программу с sudo.")
            return
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
        def sniff_worker():
            try:
                sniff(iface=iface, filter=fltr if fltr else None, prn=self.packet_callback,
                      store=False, stop_filter=lambda x: self.sniff_stop.is_set())
            except Exception as e:
                print(f"Ошибка перехвата: {e}")
                GLib.idle_add(self.intercept_status.set_text, f"Ошибка: {e}")
            finally:
                self.sniffing_running = False
                GLib.idle_add(self.intercept_start_btn.set_sensitive, True)
                GLib.idle_add(self.intercept_stop_btn.set_sensitive, False)
                if not self.sniff_stop.is_set():
                    GLib.idle_add(self.intercept_status.set_text, "Перехват завершен (лимит)")
                else:
                    GLib.idle_add(self.intercept_status.set_text, "Перехват остановлен вручную")
        self.sniff_thread = threading.Thread(target=sniff_worker, daemon=True)
        self.sniff_thread.start()

    def stop_sniff(self, w):
        if self.sniffing_running:
            self.sniff_stop.set()
            self.intercept_status.set_text("Остановка перехвата...")

    def on_packet_selected(self, selection):
        model, treeiter = selection.get_selected()
        if treeiter:
            pkt = model[treeiter][5]
            if pkt:
                summary = pkt.summary()
                details = pkt.show(dump=True)
                buffer = self.intercept_details.get_buffer()
                buffer.set_text(f"=== Summary ===\n{summary}\n=== Details ===\n{details}")

    def edit_selected_packet(self, w):
        selection = self.intercept_tree.get_selection()
        model, treeiter = selection.get_selected()
        if treeiter:
            pkt = model[treeiter][5]
            dialog = PacketEditorDialog(self.root, pkt, self.on_packet_edited)
            dialog.show_all()
        else:
            self.show_warning("Ошибка", "Выберите пакет для редактирования")

    def on_packet_edited(self, edited_pkt, success):
        if success:
            self.edited_packet = edited_pkt
            self.status_var.set_label("Пакет отредактирован, готов к отправке")

    def replay_selected_packet(self, w):
        pkt_to_send = None
        if self.edited_packet:
            pkt_to_send = self.edited_packet
        else:
            selection = self.intercept_tree.get_selection()
            model, treeiter = selection.get_selected()
            if treeiter:
                pkt_to_send = model[treeiter][5]
        if pkt_to_send:
            iface = self.intercept_iface.get_active_text()
            try:
                sendp(pkt_to_send, iface=iface, verbose=False)
                self.status_var.set_label("Пакет отправлен")
            except Exception as e:
                self.show_warning("Ошибка", f"Не удалось отправить: {e}")
        else:
            self.show_warning("Ошибка", "Нет пакета для отправки")

    # ===== Вкладка Помощь =====
    def create_help_tab(self):
        outer_scroll = Gtk.ScrolledWindow()
        outer_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        tab.set_margin_start(10); tab.set_margin_end(10)
        tab.set_margin_top(10); tab.set_margin_bottom(10)

        textview = Gtk.TextView()
        textview.set_editable(False)
        textview.set_wrap_mode(Gtk.WrapMode.WORD)
        textbuffer = textview.get_buffer()
        textbuffer.set_text(
            "Gotcha Linux - Инструментарий для тестирования сетевой безопасности\n\n"
            "Инструкции по использованию:\n"
            "- Вкладка 'Доступ': базовые сетевые утилиты (ping, сканирование портов и т.д.)\n"
            "- Вкладка 'Intercept': перехват пакетов с фильтрацией по типам.\n"
            "  * Чекбоксы выбирают типы пакетов, BPF-фильтр собирается автоматически\n"
            "  * '0' в лимитах = бесконечный захват\n"
            "- Вкладка 'DHCP Starvation': исчерпывает IP-адреса DHCP-сервера\n"
            "- Вкладка 'ARP Spoofing': атака типа 'человек посередине'\n"
            "- Вкладка 'DoS атака': генерирует трафик для отказа в обслуживании\n"
            "- Вкладка 'DNS Spoofing': ARP + DNS спуфинг\n"
            "- Вкладка 'MAC Flood': заполняет таблицу MAC-адресов коммутатора\n"
            "\nИнтерфейс использует глобальную GTK-тему системы.\n"
            "Все атакующие функции требуют прав root.\n"
            "Авторские права (c) 2026"
        )
        tab.pack_start(textview, True, True, 0)

        outer_scroll.add(tab)
        self.notebook.append_page(outer_scroll, Gtk.Label(label="Помощь"))

    def on_closing(self, widget):
        self.stop_all(None)
        Gtk.main_quit()

    def run(self):
        Gtk.main()

if __name__ == '__main__':
    app = GotchaGTK()
    app.run()
