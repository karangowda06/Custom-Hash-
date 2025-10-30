# Custom-Hash-
# 🔐 Custom Hash GUI — Educational Hashing & Comparison Tool

A Python Tkinter application that implements a **custom 128-bit hash function** and compares it against **SHA-256**. The tool displays hashes side-by-side and computes **Hamming distances** to visualize avalanche effects and hash uniqueness.

> ⚠️ **This hashing algorithm is strictly for educational and experimental purposes.**  
> It is **not secure** and must not be used for real cryptographic applications.

---

## ✨ Features

| Feature | Description |
|--------|-------------|
| Custom 128-bit Hash Function | Per-byte mixing, modular arithmetic, and bit rotations |
| SHA-256 Comparison | Displays full hash + truncated leftmost 128 bits |
| Hamming Distance | See bit differences between hash outputs |
| Avalanche Testing | View hash sensitivity on small input changes |
| Preset Input Tests | Common test strings preconfigured |
| Clipboard Copy | Quickly copy the last custom hash result |
| GUI-based | No command-line knowledge required |

---

## 🖥 GUI Overview

- Input any UTF-8 text
- Compute:
  - ✅ Custom hash only
  - ✅ SHA-256 only
  - ✅ Both + Hamming distance
- Run automated:
  - 🔹 Preset test suite
  - 🔹 Avalanche effect comparisons

The app outputs results in a monospace formatted panel for readability.

---

## 📦 Installation & Usage

### ✅ Requirements
- Python 3.7+
- Standard library only (no external dependencies)

### ▶️ Run the Application

```bash
python tk_hash_gui.py
sudo apt-get install python3-tk  # Linux
brew install python-tk          # macOS (if needed)
