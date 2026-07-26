#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GLib

import subprocess
import threading
import queue
import os
import signal
import time
import sys
import re
import socket
import ipaddress
import tempfile
import webbrowser
from datetime import datetime

# Scapy
try:
    from scapy.all import sniff, sendp, Ether, IP, TCP, UDP, ICMP, ARP, RandMAC, RandIP, Raw, get_if_hwaddr, srp
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.dns import DNS, DNSQR, DNSRR
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

# ========== Класс лога (безопасный) ==========
class LogWidget(Gtk.ScrolledWindow):
    def __init__(self, height=300):
        super().__init__()
        self.set_min_content_height(height)
        self.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
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
        eth_grid.set_column_spacing(5)
        eth_grid.set_row_spacing(5)
        eth_grid.set_margin_start(5)
        eth_grid.set_margin_end(5)
        eth_grid.set_margin_top(5)
        eth_grid.set_margin_bottom(5)
        eth_frame.add(eth_grid)
        eth_grid.attach(Gtk.Label(label="Source MAC:"), 0, 0, 1, 1)
        self.eth_src = Gtk.Entry()
        self.eth_src.set_width_chars(20)
        eth_grid.attach(self.eth_src, 1, 0, 1, 1)
        eth_grid.attach(Gtk.Label(label="Dest MAC:"), 0, 1, 1, 1)
        self.eth_dst = Gtk.Entry()
        self.eth_dst.set_width_chars(20)
        eth_grid.attach(self.eth_dst, 1, 1, 1, 1)
        vbox.pack_start(eth_frame, False, False, 0)

        ip_frame = Gtk.Frame(label="IP")
        ip_grid = Gtk.Grid()
        ip_grid.set_column_spacing(5)
        ip_grid.set_row_spacing(5)
        ip_grid.set_margin_start(5)
        ip_grid.set_margin_end(5)
        ip_grid.set_margin_top(5)
        ip_grid.set_margin_bottom(5)
        ip_frame.add(ip_grid)
        ip_grid.attach(Gtk.Label(label="Source IP:"), 0, 0, 1, 1)
        self.ip_src = Gtk.Entry()
        self.ip_src.set_width_chars(20)
        ip_grid.attach(self.ip_src, 1, 0, 1, 1)
        ip_grid.attach(Gtk.Label(label="Dest IP:"), 0, 1, 1, 1)
        self.ip_dst = Gtk.Entry()
        self.ip_dst.set_width_chars(20)
        ip_grid.attach(self.ip_dst, 1, 1, 1, 1)
        ip_grid.attach(Gtk.Label(label="TTL:"), 0, 2, 1, 1)
        self.ip_ttl = Gtk.Entry()
        self.ip_ttl.set_width_chars(10)
        ip_grid.attach(self.ip_ttl, 1, 2, 1, 1)
        vbox.pack_start(ip_frame, False, False, 0)

        trans_frame = Gtk.Frame(label="Transport")
        trans_grid = Gtk.Grid()
        trans_grid.set_column_spacing(5)
        trans_grid.set_row_spacing(5)
        trans_grid.set_margin_start(5)
        trans_grid.set_margin_end(5)
        trans_grid.set_margin_top(5)
        trans_grid.set_margin_bottom(5)
        trans_frame.add(trans_grid)
        trans_grid.attach(Gtk.Label(label="Protocol:"), 0, 0, 1, 1)
        self.proto_combo = Gtk.ComboBoxText()
        for p in ["TCP", "UDP", "ICMP", "RAW"]:
            self.proto_combo.append_text(p)
        self.proto_combo.set_active(0)
        trans_grid.attach(self.proto_combo, 1, 0, 1, 1)
        trans_grid.attach(Gtk.Label(label="Source Port:"), 0, 1, 1, 1)
        self.src_port = Gtk.Entry()
        self.src_port.set_width_chars(10)
        trans_grid.attach(self.src_port, 1, 1, 1, 1)
        trans_grid.attach(Gtk.Label(label="Dest Port:"), 0, 2, 1, 1)
        self.dst_port = Gtk.Entry()
        self.dst_port.set_width_chars(10)
        trans_grid.attach(self.dst_port, 1, 2, 1, 1)
        vbox.pack_start(trans_frame, False, False, 0)

        flags_frame = Gtk.Frame(label="TCP Flags")
        flags_box = Gtk.Box(spacing=5)
        flags_box.set_margin_start(5)
        flags_box.set_margin_end(5)
        flags_box.set_margin_top(5)
        flags_box.set_margin_bottom(5)
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
        scrolled.add(self.payload_text)
        payload_frame.add(scrolled)
        vbox.pack_start(payload_frame, True, True, 0)

        btn_box = Gtk.Box(spacing=10)
        btn_box.set_margin_start(10)
        btn_box.set_margin_end(10)
        btn_box.set_margin_top(10)
        btn_box.set_margin_bottom(10)
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
        self.bin_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'bin')
        self.interfaces = get_network_interfaces()
        self.iface_list = list(self.interfaces.keys())

        self.attack_running = False
        self.current_process = None
        self.stop_event = threading.Event()
        self.output_queue = queue.Queue()
        self.start_buttons = []
        self.stop_buttons = []
        self.log_widgets = {}
        self.status_labels = {}
        self.stats_timers = {}

        # Для перехвата
        self.sniffing_running = False
        self.sniff_thread = None
        self.captured_packets = []
        self.selected_packet = None
        self.captured_packet = None
        self.edited_packet = None
        self.packet_counter = 0
        self.sniff_stop = threading.Event()

        # Блокировка для вкладки "Доступ"
        self.access_lock = threading.Lock()
        self.access_running = False

        # Статистика
        self.dhcp_stats = {'start_time':0,'sent_packets':0,'unique_macs':0,'last_update':0,'last_sent':0}
        self.dhcp_offered_ips = set()
        self.dhcp_lock = threading.Lock()
        self.arp_stats = {'start_time':0,'sent_packets':0,'last_update':0,'last_sent':0}
        self.dos_stats = {'start_time':0,'sent_packets':0,'last_update':0,'last_sent':0}
        self.dns_stats = {'start_time':0,'intercepted':0,'spoofed':0,'last_update':0,'last_intercepted':0,'last_spoofed':0}
        self.mac_stats = {'start_time':0,'sent_frames':0,'last_update':0,'last_sent':0}
        self.dns_spoof_rules = {}
        self.dns_spoof_lock = threading.Lock()

        self.build_gui()

        if not is_root():
            self.show_warning("Внимание", "Некоторые функции требуют прав root.\nЗапустите программу с sudo.")
        self.root.connect("destroy", self.on_closing)

    def build_gui(self):
        self.root = Gtk.Window(title="Gotcha Linux")
        self.root.set_default_size(1200, 800)
        self.root.set_position(Gtk.WindowPosition.CENTER)

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        main_box.set_margin_start(10)
        main_box.set_margin_end(10)
        main_box.set_margin_top(10)
        main_box.set_margin_bottom(10)
        self.root.add(main_box)

        header = Gtk.Label()
        header.set_markup("<span size='x-large' weight='bold'>Gotcha Linux</span>")
        main_box.pack_start(header, False, False, 0)

        self.notebook = Gtk.Notebook()
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
        return combo

    def create_entry(self, default='', width=20):
        entry = Gtk.Entry()
        entry.set_text(default)
        entry.set_width_chars(width)
        return entry

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
        self.start_buttons.append(start_btn)
        self.stop_buttons.append(stop_btn)
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
                    universal_newlines=True,
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
        if self.attack_running:
            for log, status in zip(self.log_widgets.values(), self.status_labels.values()):
                self.stop_binary(log, status)
        if self.sniffing_running:
            self.stop_sniff(None)
        self.status_var.set_label("Остановлено все")

    def _parse_stats(self, line):
        # DHCP
        if "[CAPTURED]" in line:
            match = re.search(r"->\s*([\d.]+)", line)
            if match:
                with self.dhcp_lock:
                    self.dhcp_offered_ips.add(match.group(1))
                self._update_dhcp_stats()
        elif "[STATS]" in line:
            sent = re.search(r"Sent:\s*(\d+)", line)
            unique = re.search(r"Unique MACs:\s*(\d+)", line)
            captured = re.search(r"Captured IPs:\s*(\d+)", line)
            if sent:
                self.dhcp_stats['sent_packets'] = int(sent.group(1))
            if unique:
                self.dhcp_stats['unique_macs'] = int(unique.group(1))
            if captured:
                self._update_dhcp_stats()
        if "Sent Discover" in line:
            self.dhcp_stats['sent_packets'] += 1
            self._update_dhcp_stats()

        # ARP
        if "Sending ARP" in line:
            self.arp_stats['sent_packets'] += 1
            self._update_arp_stats()

        # DoS
        if "Packets:" in line:
            match = re.search(r"Packets:\s*(\d+)", line)
            if match:
                self.dos_stats['sent_packets'] = int(match.group(1))
                self._update_dos_stats()
        if "PPS:" in line:
            match = re.search(r"PPS:\s*([\d.]+)", line)
            if match:
                rate = float(match.group(1))
                try:
                    self.dos_rate_label.set_text(str(int(rate)))
                except:
                    pass

        # DNS
        if "[SPOOF]" in line:
            self.dns_stats['spoofed'] += 1
            self._update_dns_stats()
        elif "[PASS]" in line:
            self.dns_stats['intercepted'] += 1
            self._update_dns_stats()

        # MAC
        if "Total frames sent:" in line:
            match = re.search(r"Total frames sent:\s*(\d+)", line)
            if match:
                self.mac_stats['sent_frames'] = int(match.group(1))
                self._update_mac_stats()

    def _update_dhcp_stats(self):
        if not self.dhcp_attack_running:
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
        hours = int(duration//3600); minutes = int((duration%3600)//60); seconds = int(duration%60)
        self.dhcp_time_label.set_text(f"{hours:02d}:{minutes:02d}:{seconds:02d}")

    def _update_arp_stats(self):
        if not self.arp_running:
            return
        now = time.time()
        duration = now - self.arp_stats['start_time']
        if now - self.arp_stats['last_update'] >= 1:
            rate = (self.arp_stats['sent_packets'] - self.arp_stats.get('last_sent', 0)) / (now - self.arp_stats['last_update']) if now - self.arp_stats['last_update'] > 0 else 0
            self.arp_rate_label.set_text(str(int(rate)))
            self.arp_stats['last_update'] = now
            self.arp_stats['last_sent'] = self.arp_stats['sent_packets']
        self.arp_sent_label.set_text(str(self.arp_stats['sent_packets']))
        hours = int(duration//3600); minutes = int((duration%3600)//60); seconds = int(duration%60)
        self.arp_time_label.set_text(f"{hours:02d}:{minutes:02d}:{seconds:02d}")

    def _update_dos_stats(self):
        if not self.dos_running:
            return
        now = time.time()
        duration = now - self.dos_stats['start_time']
        if now - self.dos_stats['last_update'] >= 1:
            rate = (self.dos_stats['sent_packets'] - self.dos_stats.get('last_sent', 0)) / (now - self.dos_stats['last_update']) if now - self.dos_stats['last_update'] > 0 else 0
            self.dos_rate_label.set_text(str(int(rate)))
            self.dos_stats['last_update'] = now
            self.dos_stats['last_sent'] = self.dos_stats['sent_packets']
        self.dos_sent_label.set_text(str(self.dos_stats['sent_packets']))
        hours = int(duration//3600); minutes = int((duration%3600)//60); seconds = int(duration%60)
        self.dos_time_label.set_text(f"{hours:02d}:{minutes:02d}:{seconds:02d}")

    def _update_dns_stats(self):
        if not self.dns_running:
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
        hours = int(duration//3600); minutes = int((duration%3600)//60); seconds = int(duration%60)
        self.dns_time_label.set_text(f"{hours:02d}:{minutes:02d}:{seconds:02d}")

    def _update_mac_stats(self):
        if not self.mac_running:
            return
        now = time.time()
        duration = now - self.mac_stats['start_time']
        if now - self.mac_stats['last_update'] >= 1:
            rate = (self.mac_stats['sent_frames'] - self.mac_stats.get('last_sent', 0)) / (now - self.mac_stats['last_update']) if now - self.mac_stats['last_update'] > 0 else 0
            self.mac_rate_label.set_text(str(int(rate)))
            self.mac_stats['last_update'] = now
            self.mac_stats['last_sent'] = self.mac_stats['sent_frames']
        self.mac_sent_label.set_text(str(self.mac_stats['sent_frames']))
        hours = int(duration//3600); minutes = int((duration%3600)//60); seconds = int(duration%60)
        self.mac_time_label.set_text(f"{hours:02d}:{minutes:02d}:{seconds:02d}")

    def start_stats_timer(self, name):
        if name in self.stats_timers:
            GLib.source_remove(self.stats_timers[name])
        self.stats_timers[name] = GLib.timeout_add_seconds(1, self._update_stats_cb, name)

    def _update_stats_cb(self, name):
        if name == 'dhcp':
            self._update_dhcp_stats()
        elif name == 'arp':
            self._update_arp_stats()
        elif name == 'dos':
            self._update_dos_stats()
        elif name == 'dns':
            self._update_dns_stats()
        elif name == 'mac':
            self._update_mac_stats()
        return True

    # ===== Вкладка Доступ =====
    def create_access_tab(self):
        tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        tab.set_margin_start(10)
        tab.set_margin_end(10)
        tab.set_margin_top(10)
        tab.set_margin_bottom(10)

        params = Gtk.Frame(label="Базовые функции доступа")
        grid = Gtk.Grid()
        grid.set_column_spacing(10)
        grid.set_row_spacing(5)
        grid.set_margin_start(5)
        grid.set_margin_end(5)
        grid.set_margin_top(5)
        grid.set_margin_bottom(5)
        params.add(grid)
        grid.attach(Gtk.Label(label="IP адрес:"), 0, 0, 1, 1)
        self.access_ip = Gtk.Entry()
        self.access_ip.set_text("192.168.1.1")
        self.access_ip.set_width_chars(18)
        grid.attach(self.access_ip, 1, 0, 1, 1)
        grid.attach(Gtk.Label(label="Интерфейс:"), 0, 1, 1, 1)
        self.access_iface = self.create_iface_combo()
        grid.attach(self.access_iface, 1, 1, 1, 1)
        btn_box = Gtk.Box(spacing=5)
        grid.attach(btn_box, 0, 2, 2, 1)
        for label, cb in [("ICMP Ping", self.on_ping), ("Port Scan", self.on_port_scan),
                          ("Traceroute", self.on_traceroute), ("Таблица маршрутизации", self.on_route),
                          ("Сетевые адаптеры", self.on_adapters), ("Сканировать сеть", self.on_net_scan)]:
            btn = Gtk.Button.new_with_label(label)
            btn.connect("clicked", cb)
            btn_box.pack_start(btn, False, False, 0)
        tab.pack_start(params, False, False, 0)

        out_frame = Gtk.Frame(label="Результаты")
        self.access_log = LogWidget(400)
        out_frame.add(self.access_log)
        tab.pack_start(out_frame, True, True, 0)

        self.add_save_log_button(tab, self.access_log)
        self.notebook.append_page(tab, Gtk.Label(label="Доступ"))

    # Методы доступа с блокировкой
    def _run_access_cmd(self, cmd, log_msg):
        if self.access_running:
            self.access_log.append_safe("Операция уже выполняется, подождите...", 'warning')
            return
        self.access_running = True
        self.access_log.append_safe(log_msg, 'info')
        def worker():
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        text=True, bufsize=1)
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
        self._run_access_cmd(['route', '-n'], "=== Таблица маршрутизации ===")

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
        tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        tab.set_margin_start(10)
        tab.set_margin_end(10)
        tab.set_margin_top(10)
        tab.set_margin_bottom(10)
        grid = Gtk.Grid()
        grid.set_column_spacing(10)
        grid.set_row_spacing(5)
        tab.pack_start(grid, False, False, 0)

        grid.attach(Gtk.Label(label="Интерфейс:"), 0, 0, 1, 1)
        self.dhcp_iface = self.create_iface_combo()
        grid.attach(self.dhcp_iface, 1, 0, 1, 1)
        grid.attach(Gtk.Label(label="Размер пула:"), 0, 1, 1, 1)
        self.dhcp_pool = Gtk.Entry(); self.dhcp_pool.set_text("254"); self.dhcp_pool.set_width_chars(10)
        grid.attach(self.dhcp_pool, 1, 1, 1, 1)
        grid.attach(Gtk.Label(label="Кол-во запросов:"), 0, 2, 1, 1)
        self.dhcp_count = Gtk.Entry(); self.dhcp_count.set_text("1000"); self.dhcp_count.set_width_chars(10)
        grid.attach(self.dhcp_count, 1, 2, 1, 1)
        grid.attach(Gtk.Label(label="Задержка (сек):"), 0, 3, 1, 1)
        self.dhcp_delay = Gtk.Entry(); self.dhcp_delay.set_text("0.05"); self.dhcp_delay.set_width_chars(10)
        grid.attach(self.dhcp_delay, 1, 3, 1, 1)
        grid.attach(Gtk.Label(label="Таймаут Offer (сек):"), 0, 4, 1, 1)
        self.dhcp_offer = Gtk.Entry(); self.dhcp_offer.set_text("30"); self.dhcp_offer.set_width_chars(10)
        grid.attach(self.dhcp_offer, 1, 4, 1, 1)
        grid.attach(Gtk.Label(label="Таймаут ACK (сек):"), 0, 5, 1, 1)
        self.dhcp_ack = Gtk.Entry(); self.dhcp_ack.set_text("5"); self.dhcp_ack.set_width_chars(10)
        grid.attach(self.dhcp_ack, 1, 5, 1, 1)

        controls, self.dhcp_start_btn, self.dhcp_stop_btn = self.create_attack_controls(self.start_dhcp, self.stop_dhcp)
        tab.pack_start(controls, False, False, 0)

        stats_frame = Gtk.Frame(label="Статистика")
        stats_grid = Gtk.Grid()
        stats_grid.set_column_spacing(10)
        stats_grid.set_row_spacing(5)
        stats_grid.set_margin_start(5)
        stats_grid.set_margin_end(5)
        stats_grid.set_margin_top(5)
        stats_grid.set_margin_bottom(5)
        stats_frame.add(stats_grid)
        stats_grid.attach(Gtk.Label(label="Отправлено пакетов:"), 0, 0, 1, 1)
        self.dhcp_sent_label = Gtk.Label(label="0"); stats_grid.attach(self.dhcp_sent_label, 1, 0, 1, 1)
        stats_grid.attach(Gtk.Label(label="Скорость (pps):"), 0, 1, 1, 1)
        self.dhcp_rate_label = Gtk.Label(label="0"); stats_grid.attach(self.dhcp_rate_label, 1, 1, 1, 1)
        stats_grid.attach(Gtk.Label(label="Уникальных MAC:"), 0, 2, 1, 1)
        self.dhcp_unique_label = Gtk.Label(label="0"); stats_grid.attach(self.dhcp_unique_label, 1, 2, 1, 1)
        stats_grid.attach(Gtk.Label(label="Захваченные IP:"), 0, 3, 1, 1)
        self.dhcp_ips_label = Gtk.Label(label="0"); stats_grid.attach(self.dhcp_ips_label, 1, 3, 1, 1)
        stats_grid.attach(Gtk.Label(label="Время работы:"), 0, 4, 1, 1)
        self.dhcp_time_label = Gtk.Label(label="00:00:00"); stats_grid.attach(self.dhcp_time_label, 1, 4, 1, 1)
        tab.pack_start(stats_frame, False, False, 0)

        status_box = Gtk.Box(spacing=5)
        status_box.pack_start(Gtk.Label(label="Статус:"), False, False, 0)
        self.dhcp_status = Gtk.Label(label="Ожидание...")
        status_box.pack_start(self.dhcp_status, False, False, 0)
        tab.pack_start(status_box, False, False, 0)

        self.dhcp_log = LogWidget(300)
        tab.pack_start(self.dhcp_log, True, True, 0)
        self.add_save_log_button(tab, self.dhcp_log)
        self.notebook.append_page(tab, Gtk.Label(label="DHCP Starvation"))
        self.dhcp_attack_running = False

    def start_dhcp(self, w):
        if not is_root():
            self.show_warning("Ошибка", "Запустите программу с sudo.")
            return
        self.dhcp_attack_running = True
        self.dhcp_stats['start_time'] = time.time()
        self.dhcp_stats['sent_packets'] = 0
        self.dhcp_stats['unique_macs'] = 0
        with self.dhcp_lock:
            self.dhcp_offered_ips.clear()
        args = [self.dhcp_iface.get_active_text(), self.dhcp_pool.get_text(),
                self.dhcp_count.get_text(), self.dhcp_delay.get_text(),
                self.dhcp_offer.get_text(), self.dhcp_ack.get_text()]
        self.run_binary('dhcp_starvation', args, self.dhcp_log, self.dhcp_status,
                        self.dhcp_start_btn, self.dhcp_stop_btn)
        self.start_stats_timer('dhcp')

    def stop_dhcp(self, w):
        self.dhcp_attack_running = False
        self.stop_binary(self.dhcp_log, self.dhcp_status)

    # ===== ARP Spoofing =====
    def create_arp_tab(self):
        tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        tab.set_margin_start(10)
        tab.set_margin_end(10)
        tab.set_margin_top(10)
        tab.set_margin_bottom(10)
        grid = Gtk.Grid()
        grid.set_column_spacing(10)
        grid.set_row_spacing(5)
        tab.pack_start(grid, False, False, 0)

        grid.attach(Gtk.Label(label="Интерфейс:"), 0, 0, 1, 1)
        self.arp_iface = self.create_iface_combo()
        grid.attach(self.arp_iface, 1, 0, 1, 1)
        grid.attach(Gtk.Label(label="IP цели:"), 0, 1, 1, 1)
        self.arp_target = Gtk.Entry(); self.arp_target.set_text("192.168.1.100"); self.arp_target.set_width_chars(20)
        grid.attach(self.arp_target, 1, 1, 1, 1)
        grid.attach(Gtk.Label(label="IP шлюза:"), 0, 2, 1, 1)
        self.arp_gateway = Gtk.Entry(); self.arp_gateway.set_text("192.168.1.1"); self.arp_gateway.set_width_chars(20)
        grid.attach(self.arp_gateway, 1, 2, 1, 1)
        grid.attach(Gtk.Label(label="Интервал (сек):"), 0, 3, 1, 1)
        self.arp_interval = Gtk.Entry(); self.arp_interval.set_text("2"); self.arp_interval.set_width_chars(10)
        grid.attach(self.arp_interval, 1, 3, 1, 1)

        controls, self.arp_start_btn, self.arp_stop_btn = self.create_attack_controls(self.start_arp, self.stop_arp)
        tab.pack_start(controls, False, False, 0)

        stats_frame = Gtk.Frame(label="Статистика")
        stats_grid = Gtk.Grid()
        stats_grid.set_column_spacing(10)
        stats_grid.set_row_spacing(5)
        stats_grid.set_margin_start(5)
        stats_grid.set_margin_end(5)
        stats_grid.set_margin_top(5)
        stats_grid.set_margin_bottom(5)
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

        self.arp_log = LogWidget(300)
        tab.pack_start(self.arp_log, True, True, 0)
        self.add_save_log_button(tab, self.arp_log)
        self.notebook.append_page(tab, Gtk.Label(label="ARP Spoofing"))
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
        tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        tab.set_margin_start(10)
        tab.set_margin_end(10)
        tab.set_margin_top(10)
        tab.set_margin_bottom(10)
        grid = Gtk.Grid()
        grid.set_column_spacing(10)
        grid.set_row_spacing(5)
        tab.pack_start(grid, False, False, 0)

        grid.attach(Gtk.Label(label="IP адрес:"), 0, 0, 1, 1)
        self.dos_ip = Gtk.Entry(); self.dos_ip.set_text("192.168.1.1"); self.dos_ip.set_width_chars(20)
        grid.attach(self.dos_ip, 1, 0, 1, 1)
        grid.attach(Gtk.Label(label="Протокол:"), 0, 1, 1, 1)
        self.dos_proto = Gtk.ComboBoxText()
        for p in ["TCP","UDP","ICMP","ARP"]: self.dos_proto.append_text(p)
        self.dos_proto.set_active(0)
        grid.attach(self.dos_proto, 1, 1, 1, 1)
        grid.attach(Gtk.Label(label="Порт:"), 0, 2, 1, 1)
        self.dos_port = Gtk.Entry(); self.dos_port.set_text("80"); self.dos_port.set_width_chars(10)
        grid.attach(self.dos_port, 1, 2, 1, 1)
        grid.attach(Gtk.Label(label="Размер пакета:"), 0, 3, 1, 1)
        self.dos_size = Gtk.Entry(); self.dos_size.set_text("1024"); self.dos_size.set_width_chars(10)
        grid.attach(self.dos_size, 1, 3, 1, 1)
        grid.attach(Gtk.Label(label="MAC назначения:"), 0, 4, 1, 1)
        self.dos_mac = Gtk.Entry(); self.dos_mac.set_text("ff:ff:ff:ff:ff:ff"); self.dos_mac.set_width_chars(20)
        grid.attach(self.dos_mac, 1, 4, 1, 1)
        grid.attach(Gtk.Label(label="Время (сек):"), 0, 5, 1, 1)
        self.dos_duration = Gtk.Entry(); self.dos_duration.set_text("60"); self.dos_duration.set_width_chars(10)
        grid.attach(self.dos_duration, 1, 5, 1, 1)
        grid.attach(Gtk.Label(label="Интерфейс:"), 0, 6, 1, 1)
        self.dos_iface = self.create_iface_combo()
        grid.attach(self.dos_iface, 1, 6, 1, 1)

        self.dos_random_ip = Gtk.CheckButton(label="Случайный IP")
        self.dos_random_mac = Gtk.CheckButton(label="Случайный MAC")
        grid.attach(self.dos_random_ip, 0, 7, 1, 1)
        grid.attach(self.dos_random_mac, 0, 8, 1, 1)

        controls, self.dos_start_btn, self.dos_stop_btn = self.create_attack_controls(self.start_dos, self.stop_dos)
        tab.pack_start(controls, False, False, 0)

        stats_frame = Gtk.Frame(label="Статистика")
        stats_grid = Gtk.Grid()
        stats_grid.set_column_spacing(10)
        stats_grid.set_row_spacing(5)
        stats_grid.set_margin_start(5)
        stats_grid.set_margin_end(5)
        stats_grid.set_margin_top(5)
        stats_grid.set_margin_bottom(5)
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

        self.dos_log = LogWidget(300)
        tab.pack_start(self.dos_log, True, True, 0)
        self.add_save_log_button(tab, self.dos_log)
        self.notebook.append_page(tab, Gtk.Label(label="DoS атака"))
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
        tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        tab.set_margin_start(10)
        tab.set_margin_end(10)
        tab.set_margin_top(10)
        tab.set_margin_bottom(10)
        grid = Gtk.Grid()
        grid.set_column_spacing(10)
        grid.set_row_spacing(5)
        tab.pack_start(grid, False, False, 0)

        grid.attach(Gtk.Label(label="Интерфейс:"), 0, 0, 1, 1)
        self.dns_iface = self.create_iface_combo()
        grid.attach(self.dns_iface, 1, 0, 1, 1)
        grid.attach(Gtk.Label(label="TTL (сек):"), 0, 1, 1, 1)
        self.dns_ttl = Gtk.Entry(); self.dns_ttl.set_text("5"); self.dns_ttl.set_width_chars(10)
        grid.attach(self.dns_ttl, 1, 1, 1, 1)
        self.dns_catchall = Gtk.CheckButton(label="Подменять все запросы (catch-all)")
        grid.attach(self.dns_catchall, 0, 2, 2, 1)

        controls, self.dns_start_btn, self.dns_stop_btn = self.create_attack_controls(self.start_dns, self.stop_dns)
        tab.pack_start(controls, False, False, 0)

        rules_frame = Gtk.Frame(label="Правила подмены (домен → IP)")
        rules_grid = Gtk.Grid()
        rules_grid.set_column_spacing(10)
        rules_grid.set_row_spacing(5)
        rules_grid.set_margin_start(5)
        rules_grid.set_margin_end(5)
        rules_grid.set_margin_top(5)
        rules_grid.set_margin_bottom(5)
        rules_frame.add(rules_grid)
        rules_grid.attach(Gtk.Label(label="Домен:"), 0, 0, 1, 1)
        self.dns_domain_entry = Gtk.Entry(); self.dns_domain_entry.set_width_chars(20)
        rules_grid.attach(self.dns_domain_entry, 1, 0, 1, 1)
        rules_grid.attach(Gtk.Label(label="IP:"), 0, 1, 1, 1)
        self.dns_ip_entry = Gtk.Entry(); self.dns_ip_entry.set_width_chars(15)
        rules_grid.attach(self.dns_ip_entry, 1, 1, 1, 1)
        add_rule = Gtk.Button.new_with_label("Добавить")
        add_rule.connect("clicked", self.add_dns_rule)
        rules_grid.attach(add_rule, 0, 2, 1, 1)
        del_rule = Gtk.Button.new_with_label("Удалить")
        del_rule.connect("clicked", self.del_dns_rule)
        rules_grid.attach(del_rule, 1, 2, 1, 1)

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
        stats_grid.set_column_spacing(10)
        stats_grid.set_row_spacing(5)
        stats_grid.set_margin_start(5)
        stats_grid.set_margin_end(5)
        stats_grid.set_margin_top(5)
        stats_grid.set_margin_bottom(5)
        stats_frame.add(stats_grid)
        stats_grid.attach(Gtk.Label(label="Перехвачено запросов:"), 0, 0, 1, 1)
        self.dns_intercepted_label = Gtk.Label(label="0"); stats_grid.attach(self.dns_intercepted_label, 1, 0, 1, 1)
        stats_grid.attach(Gtk.Label(label="Отправлено подмен:"), 0, 1, 1, 1)
        self.dns_spoofed_label = Gtk.Label(label="0"); stats_grid.attach(self.dns_spoofed_label, 1, 1, 1, 1)
        stats_grid.attach(Gtk.Label(label="Скорость (spo/s):"), 0, 2, 1, 1)
        self.dns_rate_label = Gtk.Label(label="0"); stats_grid.attach(self.dns_rate_label, 1, 2, 1, 1)
        stats_grid.attach(Gtk.Label(label="Время работы:"), 0, 3, 1, 1)
        self.dns_time_label = Gtk.Label(label="00:00:00"); stats_grid.attach(self.dns_time_label, 1, 3, 1, 1)
        tab.pack_start(stats_frame, False, False, 0)

        status_box = Gtk.Box(spacing=5)
        status_box.pack_start(Gtk.Label(label="Статус:"), False, False, 0)
        self.dns_status = Gtk.Label(label="Ожидание...")
        status_box.pack_start(self.dns_status, False, False, 0)
        tab.pack_start(status_box, False, False, 0)

        self.dns_log = LogWidget(300)
        tab.pack_start(self.dns_log, True, True, 0)
        self.add_save_log_button(tab, self.dns_log)
        self.notebook.append_page(tab, Gtk.Label(label="DNS Spoofing"))
        self.dns_running = False

    def add_dns_rule(self, w):
        dom = self.dns_domain_entry.get_text().strip()
        ip = self.dns_ip_entry.get_text().strip()
        if not dom or not ip:
            self.dns_log.append_safe("Заполните оба поля", 'warning')
            return
        try:
            ipaddress.ip_address(ip)
        except:
            self.dns_log.append_safe(f"Неверный IP: {ip}", 'error')
            return
        self.dns_rules_store.append([dom, ip])
        self.dns_domain_entry.set_text("")
        self.dns_ip_entry.set_text("")
        self.dns_log.append_safe(f"Правило добавлено: {dom} -> {ip}", 'success')

    def del_dns_rule(self, w):
        sel = self.dns_rules_tree.get_selection()
        model, iter = sel.get_selected()
        if iter:
            model.remove(iter)
            self.dns_log.append_safe("Правило удалено", 'info')
        else:
            self.dns_log.append_safe("Выберите правило для удаления", 'warning')

    def start_dns(self, w):
        if not is_root():
            self.show_warning("Ошибка", "Запустите программу с sudo.")
            return
        if self.dns_rules_store.iter_n_children(None) == 0 and not self.dns_catchall.get_active():
            self.dns_log.append_safe("Нет правил подмены", 'warning')
            return
        fd, path = tempfile.mkstemp(suffix='.hosts')
        with os.fdopen(fd, 'w') as f:
            if self.dns_catchall.get_active():
                iter = self.dns_rules_store.get_iter_first()
                if iter:
                    ip = self.dns_rules_store[iter][1]
                    f.write(f"* {ip}\n")
            else:
                for row in self.dns_rules_store:
                    f.write(f"{row[1]} {row[0]}\n")
        self.dns_running = True
        self.dns_stats['start_time'] = time.time()
        self.dns_stats['intercepted'] = 0
        self.dns_stats['spoofed'] = 0
        args = ['-i', self.dns_iface.get_active_text(), '-f', path]
        self.run_binary('dnsspoof', args, self.dns_log, self.dns_status,
                        self.dns_start_btn, self.dns_stop_btn)
        self.start_stats_timer('dns')

    def stop_dns(self, w):
        self.dns_running = False
        self.stop_binary(self.dns_log, self.dns_status)

    # ===== MAC flood =====
    def create_mac_tab(self):
        tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        tab.set_margin_start(10)
        tab.set_margin_end(10)
        tab.set_margin_top(10)
        tab.set_margin_bottom(10)
        grid = Gtk.Grid()
        grid.set_column_spacing(10)
        grid.set_row_spacing(5)
        tab.pack_start(grid, False, False, 0)

        grid.attach(Gtk.Label(label="Интерфейс:"), 0, 0, 1, 1)
        self.mac_iface = self.create_iface_combo()
        grid.attach(self.mac_iface, 1, 0, 1, 1)
        grid.attach(Gtk.Label(label="Время (сек):"), 0, 1, 1, 1)
        self.mac_duration = Gtk.Entry(); self.mac_duration.set_text("60"); self.mac_duration.set_width_chars(10)
        grid.attach(self.mac_duration, 1, 1, 1, 1)
        grid.attach(Gtk.Label(label="MAC назначения:"), 0, 2, 1, 1)
        self.mac_dst = Gtk.Entry(); self.mac_dst.set_text("ff:ff:ff:ff:ff:ff"); self.mac_dst.set_width_chars(20)
        grid.attach(self.mac_dst, 1, 2, 1, 1)
        self.mac_random = Gtk.CheckButton(label="Случайный MAC источника")
        grid.attach(self.mac_random, 0, 3, 2, 1)

        controls, self.mac_start_btn, self.mac_stop_btn = self.create_attack_controls(self.start_mac, self.stop_mac)
        tab.pack_start(controls, False, False, 0)

        stats_frame = Gtk.Frame(label="Статистика")
        stats_grid = Gtk.Grid()
        stats_grid.set_column_spacing(10)
        stats_grid.set_row_spacing(5)
        stats_grid.set_margin_start(5)
        stats_grid.set_margin_end(5)
        stats_grid.set_margin_top(5)
        stats_grid.set_margin_bottom(5)
        stats_frame.add(stats_grid)
        stats_grid.attach(Gtk.Label(label="Отправлено кадров:"), 0, 0, 1, 1)
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

        self.mac_log = LogWidget(300)
        tab.pack_start(self.mac_log, True, True, 0)
        self.add_save_log_button(tab, self.mac_log)
        self.notebook.append_page(tab, Gtk.Label(label="MAC flood"))
        self.mac_running = False

    def start_mac(self, w):
        if not is_root():
            self.show_warning("Ошибка", "Запустите программу с sudo.")
            return
        self.mac_running = True
        self.mac_stats['start_time'] = time.time()
        self.mac_stats['sent_frames'] = 0
        args = [self.mac_iface.get_active_text(), self.mac_duration.get_text(),
                self.mac_dst.get_text()]
        if self.mac_random.get_active():
            args.append('--random-mac')
        self.run_binary('mac_flood', args, self.mac_log, self.mac_status,
                        self.mac_start_btn, self.mac_stop_btn)
        self.start_stats_timer('mac')

    def stop_mac(self, w):
        self.mac_running = False
        self.stop_binary(self.mac_log, self.mac_status)

    # ===== Перехват =====
    def create_intercept_tab(self):
        tab = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        tab.set_margin_start(10)
        tab.set_margin_end(10)
        tab.set_margin_top(10)
        tab.set_margin_bottom(10)

        left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        tab.pack_start(left, True, True, 0)

        params = Gtk.Frame(label="Параметры перехвата")
        grid = Gtk.Grid()
        grid.set_column_spacing(5)
        grid.set_row_spacing(5)
        grid.set_margin_start(5)
        grid.set_margin_end(5)
        grid.set_margin_top(5)
        grid.set_margin_bottom(5)
        params.add(grid)
        grid.attach(Gtk.Label(label="Интерфейс:"), 0, 0, 1, 1)
        self.int_iface = self.create_iface_combo()
        grid.attach(self.int_iface, 1, 0, 1, 1)
        grid.attach(Gtk.Label(label="Фильтр:"), 0, 1, 1, 1)
        self.int_filter = Gtk.Entry()
        self.int_filter.set_width_chars(20)
        grid.attach(self.int_filter, 1, 1, 1, 1)
        grid.attach(Gtk.Label(label="Кол-во ответов:"), 0, 2, 1, 1)
        self.int_resp = Gtk.Entry()
        self.int_resp.set_text("4")
        self.int_resp.set_width_chars(10)
        grid.attach(self.int_resp, 1, 2, 1, 1)
        grid.attach(Gtk.Label(label="Кол-во пакетов:"), 0, 3, 1, 1)
        self.int_count = Gtk.Entry()
        self.int_count.set_text("10")
        self.int_count.set_width_chars(10)
        grid.attach(self.int_count, 1, 3, 1, 1)

        btn_box = Gtk.Box(spacing=5)
        grid.attach(btn_box, 0, 4, 2, 1)
        self.int_start_btn = Gtk.Button.new_with_label("Начать перехват")
        self.int_start_btn.connect("clicked", self.start_sniff)
        btn_box.pack_start(self.int_start_btn, False, False, 0)
        self.int_stop_btn = Gtk.Button.new_with_label("Остановить")
        self.int_stop_btn.connect("clicked", self.stop_sniff)
        self.int_stop_btn.set_sensitive(False)
        btn_box.pack_start(self.int_stop_btn, False, False, 0)
        capture_btn = Gtk.Button.new_with_label("Захватить выбранный")
        capture_btn.connect("clicked", self.capture_selected)
        btn_box.pack_start(capture_btn, False, False, 0)
        edit_btn = Gtk.Button.new_with_label("Редактировать")
        edit_btn.connect("clicked", self.edit_selected)
        btn_box.pack_start(edit_btn, False, False, 0)

        left.pack_start(params, False, False, 0)

        packets_frame = Gtk.Frame(label="Перехваченные пакеты")
        self.packet_store = Gtk.ListStore(str, str, str, str, str, str, str, object)
        self.packet_tree = Gtk.TreeView(model=self.packet_store)
        self.packet_tree.set_headers_visible(True)
        cols = ["№","Время","Источник","Назначение","Протокол","Длина","Информация"]
        for i, col in enumerate(cols):
            renderer = Gtk.CellRendererText()
            column = Gtk.TreeViewColumn(col, renderer, text=i)
            column.set_resizable(True)
            self.packet_tree.append_column(column)
        self.packet_tree.connect("cursor-changed", self.on_packet_select)
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scrolled.add(self.packet_tree)
        packets_frame.add(scrolled)
        left.pack_start(packets_frame, True, True, 0)

        right = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        tab.pack_start(right, False, False, 0)

        control = Gtk.Frame(label="Управление пакетами")
        control_grid = Gtk.Grid()
        control_grid.set_column_spacing(5)
        control_grid.set_row_spacing(5)
        control_grid.set_margin_start(5)
        control_grid.set_margin_end(5)
        control_grid.set_margin_top(5)
        control_grid.set_margin_bottom(5)
        control.add(control_grid)
        control_grid.attach(Gtk.Label(label="Захваченный:"), 0, 0, 1, 1)
        self.captured_label = Gtk.Label(label="Нет")
        control_grid.attach(self.captured_label, 1, 0, 1, 1)
        control_grid.attach(Gtk.Label(label="Отредактированный:"), 0, 1, 1, 1)
        self.edited_label = Gtk.Label(label="Нет")
        control_grid.attach(self.edited_label, 1, 1, 1, 1)
        send_captured = Gtk.Button.new_with_label("Отправить захваченный")
        send_captured.connect("clicked", self.send_captured)
        control_grid.attach(send_captured, 0, 2, 2, 1)
        send_edited = Gtk.Button.new_with_label("Отправить отредактированный")
        send_edited.connect("clicked", self.send_edited)
        control_grid.attach(send_edited, 0, 3, 2, 1)
        clear_btn = Gtk.Button.new_with_label("Очистить список")
        clear_btn.connect("clicked", self.clear_packets)
        control_grid.attach(clear_btn, 0, 4, 2, 1)
        right.pack_start(control, False, False, 0)

        log_frame = Gtk.Frame(label="Лог перехвата")
        self.int_log = LogWidget(200)
        log_frame.add(self.int_log)
        right.pack_start(log_frame, True, True, 0)
        self.add_save_log_button(right, self.int_log)

        self.notebook.append_page(tab, Gtk.Label(label="Intercept"))
        self.sniffing_running = False

    def on_packet_select(self, tree):
        model, iter = tree.get_selection().get_selected()
        if iter:
            self.selected_packet = model[iter][7]

    def capture_selected(self, w):
        if self.selected_packet:
            self.captured_packet = self.selected_packet
            self.captured_label.set_text(f"Захвачен: {self.selected_packet.summary()}")
            self.int_log.append_safe(f"Пакет захвачен: {self.selected_packet.summary()}", 'success')
        else:
            self.int_log.append_safe("Сначала выберите пакет", 'warning')

    def edit_selected(self, w):
        if not self.selected_packet:
            self.int_log.append_safe("Сначала выберите пакет", 'warning')
            return
        if not SCAPY_AVAILABLE:
            self.int_log.append_safe("Scapy не установлен, редактирование недоступно", 'error')
            return
        def callback(edited, ok):
            if ok:
                self.edited_packet = edited
                self.edited_label.set_text(f"Отредактирован: {edited.summary()}")
                self.int_log.append_safe(f"Пакет отредактирован: {edited.summary()}", 'success')
        PacketEditorDialog(self.root, self.selected_packet, callback)

    def send_captured(self, w):
        if not self.captured_packet:
            self.int_log.append_safe("Нет захваченного пакета", 'warning')
            return
        if not SCAPY_AVAILABLE:
            self.int_log.append_safe("Scapy не установлен", 'error')
            return
        iface = self.int_iface.get_active_text()
        try:
            sendp(self.captured_packet, iface=iface, verbose=0)
            self.int_log.append_safe(f"Захваченный пакет отправлен на {iface}", 'success')
        except Exception as e:
            self.int_log.append_safe(f"Ошибка отправки: {e}", 'error')

    def send_edited(self, w):
        if not self.edited_packet:
            self.int_log.append_safe("Нет отредактированного пакета", 'warning')
            return
        if not SCAPY_AVAILABLE:
            self.int_log.append_safe("Scapy не установлен", 'error')
            return
        iface = self.int_iface.get_active_text()
        try:
            sendp(self.edited_packet, iface=iface, verbose=0)
            self.int_log.append_safe(f"Отредактированный пакет отправлен на {iface}", 'success')
        except Exception as e:
            self.int_log.append_safe(f"Ошибка отправки: {e}", 'error')

    def clear_packets(self, w):
        self.packet_store.clear()
        self.captured_packets.clear()
        self.selected_packet = None
        self.captured_packet = None
        self.edited_packet = None
        self.captured_label.set_text("Нет")
        self.edited_label.set_text("Нет")
        self.int_log.append_safe("Список очищен", 'info')

    def start_sniff(self, w):
        if not is_root():
            self.show_warning("Ошибка", "Запустите программу с sudo.")
            return
        if self.sniffing_running:
            return
        if not SCAPY_AVAILABLE:
            self.int_log.append_safe("Scapy не установлен", 'error')
            return
        iface = self.int_iface.get_active_text()
        filt = self.int_filter.get_text().strip() or None
        try:
            count = int(self.int_count.get_text())
        except:
            count = 10
        try:
            resp_count = int(self.int_resp.get_text())
        except:
            resp_count = 4

        self.sniffing_running = True
        self.int_start_btn.set_sensitive(False)
        self.int_stop_btn.set_sensitive(True)
        self.packet_store.clear()
        self.captured_packets.clear()
        self.packet_counter = 0
        self.sniff_stop.clear()

        self.int_log.append_safe(f"Перехват запущен на {iface}, фильтр={filt}, count={count}, responses={resp_count}", 'info')

        def callback(pkt):
            if not self.sniffing_running:
                return
            self.packet_counter += 1
            self.captured_packets.append(pkt)
            src = dst = proto = info = ""
            if pkt.haslayer(Ether):
                if pkt.haslayer(IP):
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                elif pkt.haslayer(IPv6):
                    src = pkt[IPv6].src
                    dst = pkt[IPv6].dst
                if pkt.haslayer(TCP):
                    proto = "TCP"; info = f"Ports: {pkt[TCP].sport}->{pkt[TCP].dport} Flags: {pkt[TCP].flags}"
                elif pkt.haslayer(UDP):
                    proto = "UDP"; info = f"Ports: {pkt[UDP].sport}->{pkt[UDP].dport}"
                elif pkt.haslayer(ICMP):
                    proto = "ICMP"; info = f"Type: {pkt[ICMP].type} Code: {pkt[ICMP].code}"
                else:
                    proto = "IP"
                length = len(pkt)
                timestamp = datetime.now().strftime("%H:%M:%S")
                GLib.idle_add(self._add_packet, str(self.packet_counter), timestamp, src, dst, proto, str(length), info, pkt)
                if resp_count > 0 and pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
                    try:
                        resp = IP(src=pkt[IP].dst, dst=pkt[IP].src) / ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
                        sendp(Ether()/resp, iface=iface, verbose=0)
                        GLib.idle_add(self.int_log.append_safe, f"Ответ ICMP отправлен на {pkt[IP].src}", 'info')
                    except:
                        pass

        self.sniff_thread = threading.Thread(target=self._sniff_worker,
                                              args=(iface, filt, count, callback), daemon=True)
        self.sniff_thread.start()

    def _sniff_worker(self, iface, filt, count, callback):
        try:
            sniff(iface=iface, filter=filt, count=count, prn=callback,
                  stop_filter=lambda x: not self.sniffing_running)
        except Exception as e:
            GLib.idle_add(self.int_log.append_safe, f"Ошибка сниффинга: {e}", 'error')
        finally:
            GLib.idle_add(self.stop_sniff, None)

    def _add_packet(self, num, timestamp, src, dst, proto, length, info, pkt):
        self.packet_store.append([num, timestamp, src, dst, proto, length, info, pkt])

    def stop_sniff(self, w):
        self.sniffing_running = False
        self.sniff_stop.set()
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=1)
        self.int_start_btn.set_sensitive(True)
        self.int_stop_btn.set_sensitive(False)
        self.int_log.append_safe("Перехват остановлен", 'warning')

    # ===== Справка =====
    def create_help_tab(self):
        tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        tab.set_margin_start(10)
        tab.set_margin_end(10)
        tab.set_margin_top(10)
        tab.set_margin_bottom(10)

        label = Gtk.Label()
        label.set_markup("<span size='large' weight='bold'>Руководство пользователя</span>")
        tab.pack_start(label, False, False, 0)

        desc = Gtk.Label()
        desc.set_markup(
            "Данная программа предназначена для тестирования сетевой безопасности.\n"
            "Подробная документация доступна в файле guide.html."
        )
        desc.set_justify(Gtk.Justification.CENTER)
        tab.pack_start(desc, False, False, 0)

        btn_guide = Gtk.Button.new_with_label("Открыть guide.html")
        btn_guide.connect("clicked", self._open_guide)
        tab.pack_start(btn_guide, False, False, 0)

        btn_scene = Gtk.Button.new_with_label("Открыть scheme.html (сценарии)")
        btn_scene.connect("clicked", self._open_scene)
        tab.pack_start(btn_scene, False, False, 0)

        self.notebook.append_page(tab, Gtk.Label(label="Справка"))

    def _open_guide(self, widget):
        base = os.path.dirname(os.path.abspath(__file__))
        paths = [
            os.path.join(base, "guide.html"),
            os.path.join(base, "other", "guide.html"),
            os.path.join(base, "doc", "guide.html"),
        ]
        for path in paths:
            if os.path.exists(path):
                webbrowser.open(path)
                return
        self.show_warning("Ошибка", "Файл guide.html не найден.\n"
                                    "Поместите его в папку с программой или в подпапку other/")

    def _open_scene(self, widget):
        base = os.path.dirname(os.path.abspath(__file__))
        paths = [
            os.path.join(base, "scheme.html"),
            os.path.join(base, "other", "scheme.html"),
            os.path.join(base, "doc", "scheme.html"),
        ]
        for path in paths:
            if os.path.exists(path):
                webbrowser.open(path)
                return
        self.show_warning("Ошибка", "Файл scheme.html не найден.\n"
                                    "Поместите его в папку с программой или в подпапку other/")

    # ===== Закрытие =====
    def on_closing(self, *args):
        if self.attack_running:
            self.stop_binary(None, None)
        if self.sniffing_running:
            self.stop_sniff(None)
        for btn in self.start_buttons:
            btn.set_sensitive(True)
        for btn in self.stop_buttons:
            btn.set_sensitive(False)
        Gtk.main_quit()

# ========== Запуск ==========
if __name__ == '__main__':
    if not is_root():
        print("Запустите с sudo для полной функциональности.")
    app = GotchaGTK()
    Gtk.main()