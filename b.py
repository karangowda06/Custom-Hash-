# tk_hash_gui.py
# Tkinter GUI for the educational custom hashing algorithm + comparisons
# Save and run: python tk_hash_gui.py

import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext, messagebox
import hashlib

# -------------------------
# Hash algorithm functions
# -------------------------
def rotl32(x: int, n: int) -> int:
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

def custom_hash(plaintext: str) -> str:
    """
    Deterministic custom hash returning 32 hex chars (128 bits).
    Educational only — not cryptographically secure.
    """
    data = plaintext.encode('utf-8')
    s0 = 0x243F6A88
    s1 = 0x85A308D3
    s2 = 0x13198A2E
    s3 = 0x03707344
    mix_const = 0x9E3779B1  # 2654435761

    for i, b in enumerate(data):
        m = ((b & 0xFF) << 24) | (i & 0xFFFFFF)
        s0 = (s0 + (m ^ s3) + (mix_const & 0xFFFFFFFF)) & 0xFFFFFFFF
        s1 = (s1 ^ rotl32(s0, (b % 16) + 1)) & 0xFFFFFFFF
        s2 = (s2 + (s1 * ((m | 1) & 0xFFFFFFFF))) & 0xFFFFFFFF
        s3 = rotl32((s3 ^ s2) + (m >> 8), (i % 24) + 1) & 0xFFFFFFFF
        if (i & 1) == 0:
            s0, s1 = s1 ^ s3, s0 ^ s2
        else:
            s2, s3 = s3 ^ s1, s2 ^ s0

    length = len(data) & 0xFFFFFFFF
    s0 = (s0 ^ (length + mix_const)) & 0xFFFFFFFF
    s1 = (s1 + rotl32(s0 ^ mix_const, 7)) & 0xFFFFFFFF
    s2 = (s2 ^ rotl32(s1 + length, 13)) & 0xFFFFFFFF
    s3 = (s3 + rotl32(s2 ^ mix_const, 19)) & 0xFFFFFFFF

    for r in range(4):
        s0 = (s0 + rotl32(s1 ^ (mix_const >> r), (r*3 + 5) % 32)) & 0xFFFFFFFF
        s1 = (s1 ^ rotl32((s2 + (mix_const << r)) & 0xFFFFFFFF, (r*5 + 3) % 32)) & 0xFFFFFFFF
        s2 = (s2 + rotl32(s3 ^ (length + r), (r*7 + 11) % 32)) & 0xFFFFFFFF
        s3 = (s3 ^ rotl32(s0 + (mix_const ^ r), (r*11 + 17) % 32)) & 0xFFFFFFFF

    digest = (s0.to_bytes(4, 'big') + s1.to_bytes(4, 'big') +
              s2.to_bytes(4, 'big') + s3.to_bytes(4, 'big'))
    return digest.hex()

def sha256_hex(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode('utf-8')).hexdigest()

def hamming_distance_hex(h1: str, h2: str) -> int:
    if len(h1) != len(h2):
        # if different lengths, compare up to min length (but ideally equal)
        L = min(len(h1), len(h2))
        h1 = h1[:L]
        h2 = h2[:L]
    a = int(h1, 16)
    b = int(h2, 16)
    return (a ^ b).bit_count()

# -------------------------
# GUI helpers
# -------------------------
def monospace_text(text_widget: tk.Text):
    text_widget.configure(font=("Consolas", 10))

def format_row(cols, widths):
    cells = []
    for i, c in enumerate(cols):
        s = str(c)
        cells.append(s.ljust(widths[i]))
    return " | ".join(cells)

def compute_and_display():
    txt = input_text.get("1.0", "end-1c")
    custom = custom_hash(txt)
    sha = sha256_hex(txt)
    sha_left128 = sha[:32]
    ham = hamming_distance_hex(custom, sha_left128)
    out = []
    out.append("Input (UTF-8 length: {})".format(len(txt.encode('utf-8'))))
    out.append("-" * 72)
    out.append(f"Custom hash (128-bit, 32 hex chars):\n  {custom}")
    out.append(f"SHA-256 (full, 64 hex chars):\n  {sha}")
    out.append(f"SHA-256 left-128 bits (32 hex) used for compare:\n  {sha_left128}")
    out.append(f"Hamming distance (custom vs SHA256-left128): {ham} bits")
    out.append("")
    out.append("Algorithm notes: custom hash uses per-byte mixing, rotations, 32-bit modular arithmetic, and finalization rounds.")
    output_text.configure(state='normal')
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, "\n".join(out))
    output_text.configure(state='disabled')
    # store last custom for copy
    root.last_custom_hash = custom

def compute_custom_only():
    txt = input_text.get("1.0", "end-1c")
    custom = custom_hash(txt)
    output_text.configure(state='normal')
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, f"Custom hash (32 hex):\n{custom}\n")
    output_text.configure(state='disabled')
    root.last_custom_hash = custom

def compute_sha_only():
    txt = input_text.get("1.0", "end-1c")
    sha = sha256_hex(txt)
    output_text.configure(state='normal')
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, f"SHA-256 (64 hex):\n{sha}\n")
    output_text.configure(state='disabled')

def copy_result():
    val = getattr(root, "last_custom_hash", None)
    if not val:
        messagebox.showinfo("Copy", "No custom hash computed yet.")
        return
    root.clipboard_clear()
    root.clipboard_append(val)
    messagebox.showinfo("Copy", "Custom hash copied to clipboard.")

def run_preset_tests():
    test_inputs = [
        ("empty string", ""),
        ("a", "a"),
        ("A (case change)", "A"),
        ("abc", "abc"),
        ("abd (small edit)", "abd"),
        ("quick sentence", "The quick brown fox jumps over the lazy dog"),
        ("quick sentence + .", "The quick brown fox jumps over the lazy dog."),
        ("emoji", "🔒🔑 Secure emoji test"),
        ("long 1000 x 'a'", "a" * 1000)
    ]
    rows = []
    # widths for pretty printing
    w0 = max(len(t[0]) for t in test_inputs) + 2
    w1 = 34  # custom hash col width
    w2 = 66  # sha256 col width
    header = format_row(["name", "custom_hash (32 hex)", "sha256 (64 hex)", "hamming(custom, sha_left128)"], [w0, w1, w2, 8])
    sep = "-" * len(header)
    rows.append(header)
    rows.append(sep)
    for name, s in test_inputs:
        ch = custom_hash(s)
        sh = sha256_hex(s)
        ham = hamming_distance_hex(ch, sh[:32])
        rows.append(format_row([name, ch, sh, str(ham)], [w0, w1, w2, 8]))
    output_text.configure(state='normal')
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, "\n".join(rows))
    output_text.configure(state='disabled')

def run_avalanche_tests():
    pairs = [
        ("abc", "abd"),
        ("a", "A"),
        ("", "a"),
        ("The quick brown fox jumps over the lazy dog", "The quick brown fox jumps over the lazy dog.")
    ]
    w1 = 28
    w2 = 28
    w3 = 34
    header = format_row(["input1", "input2", "hamming_custom", "hamming_sha_left128"], [w1, w2, 15, 19])
    sep = "-" * len(header)
    rows = [header, sep]
    for x, y in pairs:
        chx = custom_hash(x)
        chy = custom_hash(y)
        shx = sha256_hex(x)
        shy = sha256_hex(y)
        hd_custom = hamming_distance_hex(chx, chy)
        hd_sha = hamming_distance_hex(shx[:32], shy[:32])
        rows.append(format_row([x if x else "<empty>", y if y else "<empty>", str(hd_custom), str(hd_sha)],
                               [w1, w2, 15, 19]))
    output_text.configure(state='normal')
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, "\n".join(rows))
    output_text.configure(state='disabled')

# -------------------------
# Build GUI
# -------------------------
root = tk.Tk()
root.title("Custom Hash (128-bit) — Tkinter GUI")
root.geometry("920x600")
root.resizable(True, True)

mainframe = ttk.Frame(root, padding="8 8 8 8")
mainframe.pack(fill=tk.BOTH, expand=True)

# Input label and text
lbl = ttk.Label(mainframe, text="Input string (UTF-8):")
lbl.pack(anchor='w')

input_text = scrolledtext.ScrolledText(mainframe, wrap=tk.WORD, height=6)
input_text.pack(fill=tk.X, expand=False)
input_text.insert("1.0", "The quick brown fox jumps over the lazy dog")  # default sample
monospace_text(input_text)

# Buttons frame
btn_frame = ttk.Frame(mainframe)
btn_frame.pack(fill=tk.X, pady=8)

btn_compute = ttk.Button(btn_frame, text="Compute Custom Hash", command=compute_custom_only)
btn_compute.grid(row=0, column=0, padx=4, pady=2)

btn_sha = ttk.Button(btn_frame, text="Compute SHA-256", command=compute_sha_only)
btn_sha.grid(row=0, column=1, padx=4, pady=2)

btn_compare = ttk.Button(btn_frame, text="Compare (both + Hamming)", command=compute_and_display)
btn_compare.grid(row=0, column=2, padx=4, pady=2)

btn_preset = ttk.Button(btn_frame, text="Run Preset Tests", command=run_preset_tests)
btn_preset.grid(row=0, column=3, padx=4, pady=2)

btn_avalanche = ttk.Button(btn_frame, text="Avalanche Tests", command=run_avalanche_tests)
btn_avalanche.grid(row=0, column=4, padx=4, pady=2)

btn_copy = ttk.Button(btn_frame, text="Copy Last Custom Hash", command=copy_result)
btn_copy.grid(row=0, column=5, padx=4, pady=2)

# Output label and scrolled text
out_lbl = ttk.Label(mainframe, text="Output:")
out_lbl.pack(anchor='w', pady=(8,0))

output_text = scrolledtext.ScrolledText(mainframe, wrap=tk.NONE, height=18)
output_text.pack(fill=tk.BOTH, expand=True)
monospace_text(output_text)
output_text.configure(state='disabled')

# Status bar
status = ttk.Label(root, text="Ready", relief=tk.SUNKEN, anchor='w')
status.pack(side=tk.BOTTOM, fill=tk.X)

# Initialize last result holder
root.last_custom_hash = None

# Bindings: Ctrl+Enter to Compare, Ctrl+1 compute custom only
def key_handler(event):
    if (event.state & 0x4) and event.keysym == 'Return':  # Ctrl+Enter
        compute_and_display()
    elif (event.state & 0x4) and event.keysym == '1':  # Ctrl+1
        compute_custom_only()

root.bind_all("<Key>", lambda e: None)  # no-op to ensure focus behavior consistent
root.bind("<Control-Return>", lambda e: compute_and_display())
root.bind("<Control-1>", lambda e: compute_custom_only())

# Start GUI
root.mainloop()
