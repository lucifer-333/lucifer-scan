# LuciferScan ⚡

```
  _                 _  __             ____                  
 | |   _   _  ___  (_)/ _| ___ _ __  / ___|  ___ __ _ _ __  
 | |  | | | |/ __| | | |_ / _ \ '__| \___ \ / __/ _` | '_ \ 
 | |__| |_| | (__  | |  _|  __/ |     ___) | (_| (_| | | | |
 |_____\__,_|\___| |_|_|  \___|_|    |____/ \___\__,_|_| |_|
                     [ High-Speed Port Recon ]
```

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-red.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-black.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey.svg)]()

Fast, lightweight, multi-threaded TCP port scanner and service banner grabber written in pure Python. Built for speed, CTFs, and network recon without bloating your system with heavy dependencies.

---

## 🚀 Features

- **⚡ Blazing Fast:** Concurrent thread pool worker execution.
- **📦 Zero External Dependencies:** Built using 100% Python standard libraries (`socket`, `concurrent.futures`, `argparse`). No `pip install` required.
- **🔍 Service Detection & Banner Grabbing:** Probes ports and retrieves service banners (SSH version, web server headers, etc.).
- **🎯 Flexible Port Targeting:**
  - Common top 100 ports by default (`-p top`)
  - Specific port lists (`-p 80,443,8080`)
  - Port ranges (`-p 1-1000`)
  - Full range scan (`-p full` / `1-65535`)
- **💾 Export Options:** Save clean results into plain text (`.txt`) or structured JSON (`.json`).
- **🎨 Cross-Platform:** Colored ANSI terminal UI that works seamlessly across Linux, macOS, and Windows.

---

## 📥 Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/lucifer-scan.git
cd lucifer-scan
```

*(Optional) Make it executable on Linux/macOS:*
```bash
chmod +x lucifer.py
```

---

## 💻 Usage

```bash
python lucifer.py -t <target> [options]
```

### Options

| Flag | Argument | Description | Default |
|------|----------|-------------|---------|
| `-t`, `--target` | `TARGET` | Target hostname or IP address *(Required)* | - |
| `-p`, `--ports` | `PORTS` | Port range (e.g. `1-1000`, `80,443`, `top`, `full`) | `top` |
| `-T`, `--threads` | `INT` | Number of concurrent threads | `100` |
| `--timeout` | `FLOAT` | Connection timeout in seconds | `0.8` |
| `-b`, `--banner` | - | Enable service banner grabbing | `False` |
| `-o`, `--output` | `FILE` | Save output to file (`.txt` or `.json`) | - |
| `-q`, `--quiet` | - | Quiet mode (prints only open port numbers) | `False` |

---

## 🛠 Examples

#### 1. Quick scan of top 100 ports:
```bash
python lucifer.py -t scanme.nmap.org
```

#### 2. Scan specific range with banner grabbing enabled:
```bash
python lucifer.py -t 192.168.1.1 -p 1-1000 -b
```

#### 3. High-speed scan with 200 threads & export to JSON:
```bash
python lucifer.py -t target.com -p 1-65535 -T 200 -o scan_results.json
```

#### 4. Quick pipe-friendly port discovery:
```bash
python lucifer.py -t target.com -q
```

---

## ⚠️ Disclaimer

This tool is created for educational purposes, authorized security testing, and network administration only. Do not scan systems without prior explicit authorization from the system owner.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
