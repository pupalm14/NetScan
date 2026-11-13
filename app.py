import csv
import ctypes
from ctypes import wintypes
import ipaddress
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import win32com.client
import requests

# ==============================================================================
# НАСТРОЙКИ АВТООБНОВЛЕНИЯ И РЕЛИЗА
# ==============================================================================
CURRENT_VERSION = "1.0.0"
GITHUB_USER = "pupalm14"       # Замените на реальный логин GitHub перед релизом
GITHUB_REPO = "NetScan"         # Замените на имя репозитория

# ==============================================================================
# WINAPI & НИЗКОУРОВНЕВЫЕ СЕТЕВЫЕ ВЫЗОВЫ
# ==============================================================================
iphlpapi = ctypes.windll.iphlpapi

def send_arp(ip_str: str) -> str:
    """Определяет MAC-адрес через системный WinAPI SendARP без Npcap."""
    try:
        dest_ip = struct.unpack('<I', socket.inet_aton(ip_str))[0]
    except socket.error:
        return ""
    mac_addr = (ctypes.c_byte * 6)()
    phys_addr_len = wintypes.ULONG(6)
    ret = iphlpapi.SendARP(
        wintypes.ULONG(dest_ip),
        wintypes.ULONG(0),
        ctypes.byref(mac_addr),
        ctypes.byref(phys_addr_len)
    )
    if ret == 0:
        return ":".join(f"{b & 0xff:02X}" for b in mac_addr)
    return ""

def check_tcp_port(ip: str, port: int, timeout: float = 0.35) -> bool:
    """Быстрая проверка открытого TCP порта."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            return s.connect_ex((ip, port)) == 0
        except Exception:
            return False

def scan_ports(ip: str) -> list:
    """Сканирует базовые диагностические порты."""
    target_ports = [21, 22, 23, 80, 135, 139, 443, 445, 515, 631, 3389, 8080, 9100]
    opened = []
    for p in target_ports:
        if check_tcp_port(ip, p, timeout=0.25):
            opened.append(p)
    return opened

def get_netbios_name(ip: str) -> str:
    """Запрашивает NetBIOS Name Service (137 UDP)."""
    query = b'\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41' \
            b'\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41' \
            b'\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01'
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.4)
            s.sendto(query, (ip, 137))
            data, _ = s.recvfrom(1024)
            if len(data) > 57:
                raw_name = data[57:72].split(b'\x00')[0].split(b' ')[0]
                name = raw_name.decode('ascii', errors='ignore').strip()
                if name:
                    return name
    except Exception:
        pass
    return ""

def get_wmi_info(ip: str) -> dict:
    """Опрашивает пользователя, имя хоста и ОС удаленной Windows-машины через WMI."""
    info = {"User": "", "OS": "", "Hostname": ""}
    try:
        locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")
        service = locator.ConnectServer(ip, r"root\cimv2")
        
        for cs in service.ExecQuery("SELECT UserName, DNSHostName, Name FROM Win32_ComputerSystem"):
            if cs.UserName:
                info["User"] = cs.UserName
            if cs.DNSHostName:
                info["Hostname"] = cs.DNSHostName
            elif cs.Name:
                info["Hostname"] = cs.Name

        for os_obj in service.ExecQuery("SELECT Caption, Version FROM Win32_OperatingSystem"):
            caption = getattr(os_obj, "Caption", "")
            ver = getattr(os_obj, "Version", "")
            info["OS"] = f"{caption} ({ver})".strip() if caption else ver
    except Exception:
        pass
    return info

def classify_device(ports: list, host_name: str, wmi_info: dict) -> str:
    """Умная классификация: отделяет принтеры даже при наличии 445 порта."""
    low_name = host_name.lower()
    low_os = wmi_info.get("OS", "").lower()

    if 9100 in ports or 515 in ports or 631 in ports or "print" in low_name or "xerox" in low_name or "kyocera" in low_name or "brother" in low_name:
        return "Принтер/МФУ"
    if wmi_info.get("User") or "windows" in low_os:
        return "Рабочая станция / ПК"
    if 3389 in ports:
        return "ПК (RDP доступен)"
    if 445 in ports or 139 in ports:
        return "Windows устройство / ПК"
    if 80 in ports or 443 in ports or 8080 in ports:
        return "Веб-устройство / Роутер"
    if 22 in ports or 23 in ports:
        return "Сетевой коммутатор / Linux"
    return "Сетевой узел"

# ==============================================================================
# УДАЛЕННАЯ ТИХАЯ УСТАНОВКА ЧЕРЕЗ WMI И ПРОВОДНИК
# ==============================================================================
def install_file_remotely(target_ip: str, parent_window):
    """Диалог выбора файла, копирование на \\IP\\c$\\Windows\\Temp и фоновый запуск."""
    file_path = filedialog.askopenfilename(
        title=f"Выберите установщик для отправки на {target_ip}",
        filetypes=[
            ("Инсталляторы Windows", "*.msi;*.exe"),
            ("MSI пакеты", "*.msi"),
            ("Исполняемые файлы", "*.exe"),
            ("Все файлы", "*.*")
        ],
        parent=parent_window
    )
    if not file_path:
        return

    def _worker():
        file_name = os.path.basename(file_path)
        remote_temp_dir = rf"\\{target_ip}\c$\Windows\Temp"
        remote_target_path = os.path.join(remote_temp_dir, file_name)
        local_exec_path = rf"C:\Windows\Temp\{file_name}"

        try:
            # 1. Копируем файл через скрытую админскую шару
            shutil.copy2(file_path, remote_target_path)

            # 2. Формируем строку тихой установки
            ext = os.path.splitext(file_name)[1].lower()
            if ext == ".msi":
                cmd = f'msiexec.exe /i "{local_exec_path}" /qn /norestart'
            else:
                cmd = f'cmd.exe /c start "" /wait "{local_exec_path}" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /S /silent /quiet'

            # 3. Запуск через WMI Win32_Process.Create в нулевой (скрытой) сессии
            locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")
            service = locator.ConnectServer(target_ip, r"root\cimv2")
            startup = service.Get("Win32_ProcessStartup").SpawnInstance_()
            startup.ShowWindow = 0  # SW_HIDE

            proc = service.Get("Win32_Process")
            pid = win32com.client.VARIANT(win32com.client.pythoncom.VT_BYREF | win32com.client.pythoncom.VT_I4, 0)
            res = proc.Create(cmd, None, startup, pid)

            if res == 0:
                parent_window.after(
                    0, lambda: messagebox.showinfo(
                        "Установка запущена",
                        f"Установщик доставлен и запущен на {target_ip}!\n"
                        f"Файл: {file_name}\nPID процесса: {pid.value}\n\n"
                        "Установка выполняется в фоне без отвлечения пользователя.",
                        parent=parent_window
                    )
                )
            else:
                parent_window.after(
                    0, lambda: messagebox.showerror(
                        "Ошибка запуска",
                        f"WMI вернул код ошибки: {res}",
                        parent=parent_window
                    )
                )
        except PermissionError:
            parent_window.after(
                0, lambda: messagebox.showerror(
                    "Ошибка доступа",
                    f"Нет прав доступа к \\\\{target_ip}\\c$\\Windows\\Temp.\nЗапустите NetScan от имени администратора домена.",
                    parent=parent_window
                )
            )
        except Exception as e:
            parent_window.after(
                0, lambda: messagebox.showerror(
                    "Ошибка",
                    f"Сбой при установке на {target_ip}:\n{e}",
                    parent=parent_window
                )
            )

    threading.Thread(target=_worker, daemon=True).start()

# ==============================================================================
# АВТООБНОВЛЕНИЕ ЧЕРЕЗ GITHUB RELEASES
# ==============================================================================
def parse_semver(v_str: str) -> tuple:
    digits = re.findall(r'\d+', v_str)
    return tuple(map(int, digits)) if digits else (0, 0, 0)

def check_github_update(parent_window):
    def _worker():
        if GITHUB_USER == "ваш_логин":
            return
        api_url = f"https://api.github.com/repos/{GITHUB_USER}/{GITHUB_REPO}/releases/latest"
        try:
            resp = requests.get(api_url, timeout=3, headers={"User-Agent": "NetScan-Updater"})
            if resp.status_code != 200:
                return
            data = resp.json()
            remote_tag = data.get("tag_name", "")
            assets = data.get("assets", [])

            if parse_semver(remote_tag) > parse_semver(CURRENT_VERSION):
                download_url = next((a["browser_download_url"] for a in assets if a.get("name", "").lower().endswith(".exe")), None)
                if download_url:
                    parent_window.after(0, lambda: prompt_update(parent_window, remote_tag, download_url))
        except Exception:
            pass

    threading.Thread(target=_worker, daemon=True).start()

def prompt_update(parent_window, remote_tag, download_url):
    msg = f"Вышла новая версия: {remote_tag} (текущая: v{CURRENT_VERSION})\n\nОбновить NetScan прямо сейчас?"
    if messagebox.askyesno("Обновление NetScan", msg, parent=parent_window):
        threading.Thread(target=apply_update, args=(download_url,), daemon=True).start()

def apply_update(download_url):
    try:
        current_exe = os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__)
        new_exe = os.path.join(os.path.dirname(current_exe), "NetScan_update.exe")

        resp = requests.get(download_url, stream=True, timeout=20)
        with open(new_exe, "wb") as f:
            for chunk in resp.iter_content(chunk_size=16384):
                f.write(chunk)

        bat_path = os.path.join(tempfile.gettempdir(), "netscan_updater.bat")
        bat_content = f"""@echo off
timeout /t 1 /nobreak > nul
move /y "{new_exe}" "{current_exe}"
start "" "{current_exe}"
del "%~f0"
"""
        with open(bat_path, "w", encoding="cp866") as bf:
            bf.write(bat_content)

        subprocess.Popen(["cmd.exe", "/c", bat_path], creationflags=0x08000000, close_fds=True)
        sys.exit(0)
    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось обновить: {e}")

# ==============================================================================
# ОСНОВНОЕ GUI ПРИЛОЖЕНИЕ
# ==============================================================================
class NetScanApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NetScan - Сетевой инвентаризатор и сканер")
        self.geometry("960x620")
        self.minsize(820, 520)

        self.is_scanning = False
        self.found_devices = []

        # Попытка установить иконку
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.ico")
        if os.path.exists(icon_path):
            try:
                self.iconbitmap(icon_path)
            except Exception:
                pass

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True)

        self.tab_scan = ttk.Frame(notebook)
        self.tab_find = ttk.Frame(notebook)

        notebook.add(self.tab_scan, text="Инвентаризация сети")
        notebook.add(self.tab_find, text="Точечный поиск устройства")

        self.build_scan_tab()
        self.build_find_tab()

        # Контекстное меню
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Тихая установка ПО (через проводник)...", command=self.on_menu_install)
        self.context_menu.add_command(label="Открыть диск C$ в Проводнике", command=self.on_menu_open_c)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Скопировать IP-адрес", command=self.on_menu_copy_ip)

        # Фоновая проверка релизов через 1.5 секунды
        self.after(1500, lambda: check_github_update(self))

    # --- ВКЛАДКА 1: ИНВЕНТАРИЗАЦИЯ СЕТИ ---
    def build_scan_tab(self):
        top_frame = ttk.Frame(self.tab_scan, padding=8)
        top_frame.pack(fill="x")

        ttk.Label(top_frame, text="Подсеть (CIDR):").pack(side="left", padx=4)
        self.ent_subnet = ttk.Entry(top_frame, width=18)
        self.ent_subnet.insert(0, "192.168.1.0/24")
        self.ent_subnet.pack(side="left", padx=4)

        self.btn_scan = ttk.Button(top_frame, text="Сканировать", command=self.start_scan)
        self.btn_scan.pack(side="left", padx=4)

        self.btn_stop = ttk.Button(top_frame, text="Остановить", command=self.stop_scan, state="disabled")
        self.btn_stop.pack(side="left", padx=4)

        self.btn_export = ttk.Button(top_frame, text="Экспорт в CSV", command=self.export_csv)
        self.btn_export.pack(side="left", padx=8)

        self.lbl_status = ttk.Label(top_frame, text="Готов к работе")
        self.lbl_status.pack(side="right", padx=6)

        cols = ("ip", "mac", "type", "hostname", "user", "os", "ports")
        self.tree = ttk.Treeview(self.tab_scan, columns=cols, show="headings", selectmode="browse")
        self.tree.heading("ip", text="IP-адрес")
        self.tree.heading("mac", text="MAC-адрес")
        self.tree.heading("type", text="Тип")
        self.tree.heading("hostname", text="Имя хоста")
        self.tree.heading("user", text="Пользователь")
        self.tree.heading("os", text="Операционная система")
        self.tree.heading("ports", text="Порты")

        self.tree.column("ip", width=110, anchor="w")
        self.tree.column("mac", width=125, anchor="center")
        self.tree.column("type", width=130, anchor="w")
        self.tree.column("hostname", width=120, anchor="w")
        self.tree.column("user", width=120, anchor="w")
        self.tree.column("os", width=170, anchor="w")
        self.tree.column("ports", width=110, anchor="w")

        scrollbar = ttk.Scrollbar(self.tab_scan, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(fill="both", expand=True, side="left", padx=(8, 0), pady=6)
        scrollbar.pack(fill="y", side="right", padx=(0, 8), pady=6)

        # Привязка правого клика
        self.tree.bind("<Button-3>", self.show_context_menu)

    # --- ВКЛАДКА 2: ТОЧЕЧНЫЙ ПОИСК ---
    def build_find_tab(self):
        f_top = ttk.Frame(self.tab_find, padding=10)
        f_top.pack(fill="x")

        ttk.Label(f_top, text="Диапазон поиска:").grid(row=0, column=0, sticky="w", padx=4, pady=4)
        self.ent_find_subnet = ttk.Entry(f_top, width=20)
        self.ent_find_subnet.insert(0, "192.168.1.0/24")
        self.ent_find_subnet.grid(row=0, column=1, sticky="w", padx=4, pady=4)

        ttk.Label(f_top, text="Что искать (IP, MAC или логин):").grid(row=1, column=0, sticky="w", padx=4, pady=4)
        self.ent_find_query = ttk.Entry(f_top, width=25)
        self.ent_find_query.grid(row=1, column=1, sticky="w", padx=4, pady=4)

        self.btn_find = ttk.Button(f_top, text="Найти хост", command=self.start_targeted_find)
        self.btn_find.grid(row=1, column=2, padx=8, pady=4)

        self.find_text = tk.Text(self.tab_find, wrap="word", height=14)
        self.find_text.pack(fill="both", expand=True, padx=10, pady=8)

    # --- КОНТЕКСТНОЕ МЕНЮ И ДЕЙСТВИЯ ---
    def show_context_menu(self, event):
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
            self.context_menu.post(event.x_root, event.y_root)

    def get_selected_ip(self):
        selected = self.tree.selection()
        if not selected:
            return None
        return self.tree.item(selected[0], "values")[0]

    def on_menu_install(self):
        ip = self.get_selected_ip()
        if ip:
            install_file_remotely(ip, self)

    def on_menu_open_c(self):
        ip = self.get_selected_ip()
        if ip:
            subprocess.Popen(f'explorer.exe "\\\\{ip}\\c$"')

    def on_menu_copy_ip(self):
        ip = self.get_selected_ip()
        if ip:
            self.clipboard_clear()
            self.clipboard_append(ip)

    # --- ЛОГИКА СКАНИРОВАНИЯ ---
    def start_scan(self):
        try:
            net = ipaddress.ip_network(self.ent_subnet.get().strip(), strict=False)
        except Exception:
            messagebox.showerror("Ошибка", "Неверный формат подсети (пример: 192.168.1.0/24)")
            return

        for row in self.tree.get_children():
            self.tree.delete(row)
        self.found_devices.clear()

        self.is_scanning = True
        self.btn_scan.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.lbl_status.config(text="Идет сканирование...")

        threading.Thread(target=self._scan_thread, args=(net,), daemon=True).start()

    def stop_scan(self):
        self.is_scanning = False
        self.lbl_status.config(text="Сканирование остановлено.")
        self.btn_scan.config(state="normal")
        self.btn_stop.config(state="disabled")

    def _scan_thread(self, net):
        hosts = list(net.hosts())
        total = len(hosts)

        for idx, ip_obj in enumerate(hosts):
            if not self.is_scanning:
                break

            ip_str = str(ip_obj)
            self.lbl_status.config(text=f"Опрос {idx+1}/{total}: {ip_str}")

            mac = send_arp(ip_str)
            if not mac:
                continue

            # Хост ответил на ARP
            ports = scan_ports(ip_str)
            netbios = get_netbios_name(ip_str)
            wmi_info = get_wmi_info(ip_str) if (445 in ports or 139 in ports) else {"User": "", "OS": "", "Hostname": ""}
            
            hostname = wmi_info.get("Hostname") or netbios
            dev_type = classify_device(ports, hostname, wmi_info)
            ports_str = ",".join(map(str, ports)) if ports else "-"

            row = (ip_str, mac, dev_type, hostname or "-", wmi_info.get("User") or "-", wmi_info.get("OS") or "-", ports_str)
            self.found_devices.append(row)
            self.tree.insert("", "end", values=row)

        self.lbl_status.config(text=f"Готово! Найдено устройств: {len(self.found_devices)}")
        self.btn_scan.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.is_scanning = False

    def export_csv(self):
        if not self.found_devices:
            messagebox.showinfo("Инфо", "Таблица пуста. Нечего экспортировать.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Файлы (Excel)", "*.csv")],
            initialfile="network_inventory.csv"
        )
        if not file_path:
            return

        try:
            with open(file_path, "w", newline="", encoding="cp1251", errors="replace") as f:
                writer = csv.writer(f, delimiter=";")
                writer.writerow(["IP-адрес", "MAC-адрес", "Тип", "Имя хоста", "Пользователь", "Операционная система", "Порты"])
                for dev in self.found_devices:
                    writer.writerow(dev)
            messagebox.showinfo("Успех", f"Отчет сохранен:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить CSV: {e}")

    # --- ТОЧЕЧНЫЙ ПОИСК ---
    def start_targeted_find(self):
        query = self.ent_find_query.get().strip().lower()
        if not query:
            messagebox.showwarning("Внимание", "Введите IP, MAC или логин для поиска.")
            return

        try:
            net = ipaddress.ip_network(self.ent_find_subnet.get().strip(), strict=False)
        except Exception:
            messagebox.showerror("Ошибка", "Неверный формат подсети.")
            return

        self.find_text.delete("1.0", "end")
        self.find_text.insert("end", f"[*] Запущен поиск '{query}' в диапазоне {net}...\n\n")

        def _worker():
            for ip_obj in net.hosts():
                ip_str = str(ip_obj)
                mac = send_arp(ip_str)
                if not mac:
                    continue

                ports = scan_ports(ip_str)
                netbios = get_netbios_name(ip_str)
                wmi = get_wmi_info(ip_str) if (445 in ports or 139 in ports) else {"User": "", "OS": "", "Hostname": ""}
                user = wmi.get("User", "")
                hostname = wmi.get("Hostname") or netbios

                # Проверка совпадения
                if (query in ip_str.lower()) or (query in mac.lower().replace("-", ":")) or (query in user.lower()) or (query in hostname.lower()):
                    res = (
                        f"[+] НАЙДЕНО УСТРОЙСТВО!\n"
                        f"    IP-адрес:      {ip_str}\n"
                        f"    MAC-адрес:     {mac}\n"
                        f"    Имя хоста:     {hostname or '-'}\n"
                        f"    Пользователь:  {user or '-'}\n"
                        f"    ОС:            {wmi.get('OS') or '-'}\n"
                        f"    Порты:         {ports}\n"
                        f"----------------------------------------\n"
                    )
                    self.find_text.insert("end", res)
                    self.find_text.see("end")
                    return

            self.find_text.insert("end", "[-] Совпадений не обнаружено.\n")

        threading.Thread(target=_worker, daemon=True).start()

if __name__ == "__main__":
    app = NetScanApp()
    app.mainloop()