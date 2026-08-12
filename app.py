# -*- coding: utf-8 -*-
"""极简 VPN 客户端（第一版）

基于 mihomo (Clash Meta) 内核：
- 连接 = 启动 core/mihomo.exe（子进程、隐藏窗口）+ 打开 Windows 系统代理
- 断开 = 结束 mihomo 进程树 + 关闭系统代理（立即广播，3 秒内恢复上网）

安全策略：
- 启动内核前强制把配置改为仅本机监听（allow-lan / bind-address / dns listen）
- 程序启动时若发现系统代理开着但内核没在跑，自动清掉残留代理
- 程序退出（含异常退出）时自动清理代理并结束内核

用法：
    python app.py            # 打开图形界面
    python app.py --selftest # 无界面端到端自检（连接 -> 访问 Google -> 断开）
"""

import atexit
import os
import re
import subprocess
import sys
import threading
import time
import urllib.request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MIHOMO_EXE = os.path.join(BASE_DIR, "core", "mihomo.exe")
CONFIG_DIR = os.path.join(BASE_DIR, "config")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.yaml")

PROXY_ADDR = "127.0.0.1:7890"
CONTROLLER_URL = "http://127.0.0.1:9090/version"

CREATE_NO_WINDOW = 0x08000000
INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_REFRESH = 37

_INTERNET_SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

# ---------------------------------------------------------------------------
# 配置安全补丁：把订阅配置里对外开放的监听改回仅本机
# ---------------------------------------------------------------------------

_SECURITY_PATCHES = [
    (re.compile(r"^allow-lan:.*$", re.M), "allow-lan: false"),
    (re.compile(r"^bind-address:.*$", re.M), "bind-address: '127.0.0.1'"),
    (re.compile(r"^(\s*)listen:\s*'?0\.0\.0\.0:1053'?", re.M), r"\1listen: '127.0.0.1:1053'"),
]


def patch_config(log=print):
    """就地修补 config.yaml，幂等。"""
    with open(CONFIG_FILE, encoding="utf-8") as f:
        text = f.read()
    patched = text
    for pattern, replacement in _SECURITY_PATCHES:
        patched = pattern.sub(replacement, patched)
    if patched != text:
        with open(CONFIG_FILE, "w", encoding="utf-8", newline="\n") as f:
            f.write(patched)
        log("已应用安全补丁：内核仅监听本机地址")
    else:
        log("配置已是仅本机监听，无需打补丁")


# ---------------------------------------------------------------------------
# 地理数据库：内核启动依赖 geoip.metadb / geosite.dat，缺失时自动经镜像下载
# ---------------------------------------------------------------------------

_GEO_FILES = ("geoip.metadb", "geosite.dat")
_GEO_BASE_URL = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/"
_GEO_MIRRORS = ("https://gh-proxy.com/", "https://ghfast.top/", "")


def ensure_geo_data(log=print):
    for name in _GEO_FILES:
        path = os.path.join(CONFIG_DIR, name)
        if os.path.exists(path) and os.path.getsize(path) > 0:
            continue
        log(f"缺少地理数据文件 {name}，正在下载…")
        for prefix in _GEO_MIRRORS:
            try:
                with urllib.request.urlopen(prefix + _GEO_BASE_URL + name,
                                            timeout=60) as resp:
                    data = resp.read()
                with open(path, "wb") as f:
                    f.write(data)
                log(f"{name} 下载完成（{len(data)} 字节）")
                break
            except Exception:
                continue
        else:
            raise RuntimeError(f"地理数据文件 {name} 下载失败，内核无法启动，请检查网络后重试")


# ---------------------------------------------------------------------------
# Windows 系统代理（注册表 + WinINet 广播）
# ---------------------------------------------------------------------------

def _import_win():
    import ctypes
    import winreg
    return ctypes, winreg


def _reg_read(name, default=None):
    _, winreg = _import_win()
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INTERNET_SETTINGS_KEY, 0,
                            winreg.KEY_READ) as key:
            return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return default


def _reg_write(name, value, kind=None):
    _, winreg = _import_win()
    if kind is None:
        kind = winreg.REG_DWORD if isinstance(value, int) else winreg.REG_SZ
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INTERNET_SETTINGS_KEY, 0,
                        winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, name, 0, kind, value)


def _reg_delete(name):
    _, winreg = _import_win()
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INTERNET_SETTINGS_KEY, 0,
                            winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, name)
    except OSError:
        pass


def _notify_system():
    """广播代理设置变更，让所有程序立即生效（不用重启浏览器）。"""
    ctypes, _ = _import_win()
    wininet = ctypes.windll.wininet
    wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
    wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)


_original_proxy_server = None  # 连接前用户的原始 ProxyServer，断开时还原


def proxy_enabled():
    return bool(_reg_read("ProxyEnable", 0))


def enable_proxy():
    global _original_proxy_server
    _original_proxy_server = _reg_read("ProxyServer")
    _reg_write("ProxyEnable", 1)
    _reg_write("ProxyServer", PROXY_ADDR)
    _notify_system()


def disable_proxy():
    global _original_proxy_server
    _reg_write("ProxyEnable", 0)
    if _original_proxy_server is not None:
        _reg_write("ProxyServer", _original_proxy_server)
        _original_proxy_server = None
    else:
        _reg_delete("ProxyServer")
    _notify_system()
    # 兜底：若有外部进程用缓存值写回，强制清掉属于我们的残留
    time.sleep(0.3)
    if _reg_read("ProxyEnable", 0):
        _reg_write("ProxyEnable", 0)
    if _original_proxy_server is None and _reg_read("ProxyServer") == PROXY_ADDR:
        _reg_delete("ProxyServer")
        _notify_system()


# ---------------------------------------------------------------------------
# mihomo 子进程管理
# ---------------------------------------------------------------------------

_proc = None


def mihomo_running():
    result = subprocess.run(
        ["tasklist", "/FI", "IMAGENAME eq mihomo.exe"],
        capture_output=True, creationflags=CREATE_NO_WINDOW)
    return "mihomo.exe" in result.stdout.decode("utf-8", errors="replace").lower()


def start_mihomo():
    global _proc
    if mihomo_running():
        raise RuntimeError("检测到 mihomo 已在运行，请先关闭后重试")
    _proc = subprocess.Popen(
        [MIHOMO_EXE, "-d", CONFIG_DIR],
        cwd=BASE_DIR,
        creationflags=CREATE_NO_WINDOW,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
    return _proc


def stop_mihomo():
    """结束 mihomo 进程树；若进程句柄丢失则按镜像名兜底清理。"""
    global _proc
    if _proc is not None and _proc.poll() is None:
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(_proc.pid)],
                       capture_output=True, creationflags=CREATE_NO_WINDOW)
    elif mihomo_running():
        subprocess.run(["taskkill", "/F", "/IM", "mihomo.exe", "/T"],
                       capture_output=True, creationflags=CREATE_NO_WINDOW)
    _proc = None


def wait_ready(timeout=15.0):
    """轮询 external-controller 的 /version，确认内核就绪。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(CONTROLLER_URL, timeout=1) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


# ---------------------------------------------------------------------------
# 图形界面
# ---------------------------------------------------------------------------

def run_gui():
    import tkinter as tk
    from tkinter import scrolledtext

    class App:
        def __init__(self):
            self.connected = False
            self._busy = False

            self.root = tk.Tk()
            self.root.title("极简 VPN 客户端")
            self.root.geometry("560x380")
            self.root.resizable(False, False)

            self.status_var = tk.StringVar(value="状态：未连接")
            status_label = tk.Label(self.root, textvariable=self.status_var,
                                    anchor="w", font=("Microsoft YaHei", 11))
            status_label.pack(fill="x", padx=12, pady=(12, 4))

            self.button_var = tk.StringVar(value="连接")
            self.toggle_button = tk.Button(self.root, textvariable=self.button_var,
                                           command=self.on_toggle, width=16,
                                           font=("Microsoft YaHei", 10))
            self.toggle_button.pack(pady=6)

            log_frame = tk.Frame(self.root)
            log_frame.pack(fill="both", expand=True, padx=12, pady=(6, 12))
            self.log_text = scrolledtext.ScrolledText(log_frame, height=14,
                                                      state="disabled",
                                                      font=("Consolas", 9))
            self.log_text.pack(fill="both", expand=True)

            self.root.protocol("WM_DELETE_WINDOW", self.on_close)
            atexit.register(self.emergency_cleanup)

            self.log("程序已启动")
            self._startup_cleanup()

        # -- 线程安全的界面更新 --------------------------------------------
        def log(self, message):
            def _append():
                stamp = time.strftime("%H:%M:%S")
                self.log_text.configure(state="normal")
                self.log_text.insert("end", f"[{stamp}] {message}\n")
                self.log_text.see("end")
                self.log_text.configure(state="disabled")
            try:
                self.root.after(0, _append)
            except Exception:
                print(message)

        def set_status(self, text):
            try:
                self.root.after(0, lambda: self.status_var.set(f"状态：{text}"))
            except Exception:
                pass

        def _set_busy(self, busy):
            self._busy = busy
            state = "disabled" if busy else "normal"
            try:
                self.root.after(0, lambda: self.toggle_button.configure(state=state))
            except Exception:
                pass

        # -- 启动兜底：清理残留代理 ----------------------------------------
        def _startup_cleanup(self):
            if proxy_enabled() and not mihomo_running():
                disable_proxy()
                self.log("检测到系统代理残留（内核未运行），已自动清理")

        # -- 连接 / 断开 ----------------------------------------------------
        def on_toggle(self):
            if self._busy:
                return
            if self.connected:
                threading.Thread(target=self._disconnect_worker, daemon=True).start()
            else:
                threading.Thread(target=self._connect_worker, daemon=True).start()

        def _connect_worker(self):
            self._set_busy(True)
            self.set_status("正在连接…")
            try:
                ensure_geo_data(self.log)
                patch_config(self.log)
                self.log("正在启动 mihomo 内核…")
                start_mihomo()
                if not wait_ready():
                    stop_mihomo()
                    self.log("连接失败：内核启动超时，已回滚")
                    self.set_status("连接失败")
                    return
                enable_proxy()
                self.connected = True
                self.button_var.set("断开")
                self.set_status("已连接")
                self.log(f"连接成功：系统代理已指向 {PROXY_ADDR}")
            except Exception as exc:
                self.log(f"连接失败：{exc}")
                self.set_status("连接失败")
            finally:
                self._set_busy(False)

        def _disconnect_worker(self):
            self._set_busy(True)
            self.set_status("正在断开…")
            try:
                # 先关代理，保证浏览器立刻恢复上网
                disable_proxy()
                stop_mihomo()
                self.connected = False
                self.button_var.set("连接")
                self.set_status("未连接")
                self.log("已断开：系统代理已关闭，内核已退出")
            except Exception as exc:
                self.log(f"断开时出错：{exc}")
            finally:
                self._set_busy(False)

        # -- 退出清理 --------------------------------------------------------
        def emergency_cleanup(self):
            """atexit 兜底：无论正常还是异常退出，都不留代理残留。"""
            try:
                if proxy_enabled():
                    disable_proxy()
            except Exception:
                pass
            try:
                stop_mihomo()
            except Exception:
                pass

        def on_close(self):
            if self.connected:
                disable_proxy()
                stop_mihomo()
                self.connected = False
            self.root.destroy()

        def run(self):
            self.root.mainloop()

    App().run()


# ---------------------------------------------------------------------------
# 端到端自检（无界面）：连接 -> 通过代理访问 Google -> 断开 -> 检查残留
# ---------------------------------------------------------------------------

def selftest():
    import shutil

    failures = []

    def check(name, ok, detail=""):
        print(f"  [{'通过' if ok else '失败'}] {name}{(' - ' + detail) if detail else ''}")
        if not ok:
            failures.append(name)

    print("[1/6] 检查地理数据并应用配置安全补丁")
    ensure_geo_data()
    patch_config()

    print("[2/6] 启动内核并等待就绪")
    try:
        start_mihomo()
    except Exception as exc:
        print(f"内核启动失败：{exc}")
        return 1
    ready = wait_ready(timeout=20)
    check("内核就绪（external-controller 可访问）", ready)
    if not ready:
        stop_mihomo()
        return 1
    try:
        with urllib.request.urlopen(CONTROLLER_URL, timeout=2) as resp:
            print("      内核版本接口返回:", resp.read().decode().strip())
    except Exception:
        pass

    print("[3/6] 开启系统代理")
    enable_proxy()
    check("注册表 ProxyEnable=1", _reg_read("ProxyEnable") == 1)
    check("注册表 ProxyServer 正确", _reg_read("ProxyServer") == PROXY_ADDR,
          str(_reg_read("ProxyServer")))

    print("[4/6] 通过代理访问 https://www.google.com")
    curl = shutil.which("curl")
    if curl:
        # 冷启动时首个节点握手可能偏慢，最多重试 3 次
        code, stderr = "", ""
        for attempt in range(1, 4):
            result = subprocess.run(
                [curl, "-sS", "-x", f"http://{PROXY_ADDR}", "-o", os.devnull,
                 "-w", "%{http_code}", "--connect-timeout", "15", "--max-time", "30",
                 "https://www.google.com"],
                capture_output=True, creationflags=CREATE_NO_WINDOW)
            code = result.stdout.decode("utf-8", errors="replace").strip()
            stderr = result.stderr.decode("utf-8", errors="replace").strip()
            if result.returncode == 0 and code.isdigit() and code[0] in "23":
                break
            print(f"      第 {attempt} 次探测未通过（HTTP {code or '无响应'}），重试…")
            time.sleep(2)
        check("代理出口可达 Google", code.isdigit() and code[0] in "23",
              f"HTTP {code}" if code else stderr[:200])
    else:
        check("找到 curl", False, "PATH 中没有 curl，无法验证出口")

    print("[5/6] 断开：关闭系统代理并结束内核")
    disable_proxy()
    stop_mihomo()
    time.sleep(1.0)
    check("注册表 ProxyEnable=0（无残留）", _reg_read("ProxyEnable") == 0)
    check("ProxyServer 已还原/清除", _reg_read("ProxyServer") in (None, ""))
    check("mihomo 进程已退出", not mihomo_running())

    print("[6/6] 结果汇总")
    if failures:
        print(f"自检失败，未通过项：{failures}")
        return 1
    print("自检全部通过 [PASS]")
    return 0


def main():
    # 控制台编码兜底：遇到无法编码的字符时替换而不是崩溃
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(errors="replace")
        except Exception:
            pass
    if os.name != "nt":
        print("本程序仅支持 Windows。")
        sys.exit(1)
    if not os.path.exists(MIHOMO_EXE):
        print(f"找不到内核文件：{MIHOMO_EXE}，请先下载 mihomo。")
        sys.exit(1)
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        sys.exit(selftest())
    run_gui()


if __name__ == "__main__":
    main()
