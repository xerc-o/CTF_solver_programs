#!/usr/bin/env python3
"""
Close Prime RSA Recovery Tool
Fermat Factorization -> Private Key Reconstruction -> PEM Export
"""

from math import isqrt
import sys

try:
    from Crypto.PublicKey import RSA
except ImportError:
    RSA = None

state = {"N": None, "e": 65537, "p": None, "q": None, "d": None}


def input_modulus():
    raw = input("Masukkan N (hex, boleh ada spasi/kolon, atau desimal): ").strip()
    raw = raw.replace(":", "").replace(" ", "").replace("\n", "")
    try:
        if raw.lower().startswith("0x"):
            N = int(raw, 16)
        else:
            # coba hex dulu, kalau gagal coba desimal
            try:
                N = int(raw, 16)
            except ValueError:
                N = int(raw, 10)
    except ValueError:
        print("[!] Format N tidak valid.")
        return
    state["N"] = N
    print(f"[+] N tersimpan ({N.bit_length()} bit)")


def input_exponent():
    raw = input(f"Masukkan e (default {state['e']}): ").strip()
    if raw:
        state["e"] = int(raw)
    print(f"[+] e = {state['e']}")


def fermat_factorize():
    N = state["N"]
    if N is None:
        print("[!] N belum diisi. Pilih menu 1 dulu.")
        return

    max_iter = 10_000_000
    a = isqrt(N) + 1
    b2 = a * a - N
    count = 0

    print("[*] Menjalankan Fermat factorization...")
    while True:
        r = isqrt(b2)
        if r * r == b2:
            break
        a += 1
        b2 = a * a - N
        count += 1
        if count % 500_000 == 0:
            print(f"    iterasi: {count}")
        if count > max_iter:
            print("[!] Batas iterasi tercapai, p dan q kemungkinan tidak cukup dekat.")
            print("    Coba cek N di factordb.com sebagai alternatif.")
            return

    b = isqrt(b2)
    p = a - b
    q = a + b

    if p * q != N:
        print("[!] Verifikasi gagal, p*q != N.")
        return

    state["p"], state["q"] = p, q
    print(f"[+] Ditemukan dalam {count} iterasi")
    print(f"    p = {p}")
    print(f"    q = {q}")


def input_manual_pq():
    try:
        p = int(input("Masukkan p: ").strip())
        q = int(input("Masukkan q: ").strip())
    except ValueError:
        print("[!] Input tidak valid.")
        return
    if state["N"] and p * q != state["N"]:
        print("[!] Peringatan: p*q != N yang tersimpan. Tetap disimpan.")
    state["p"], state["q"] = p, q
    print("[+] p dan q tersimpan.")


def compute_private_key():
    p, q, e = state["p"], state["q"], state["e"]
    if not p or not q:
        print("[!] p dan q belum ada. Jalankan factorization dulu (menu 3) atau input manual (menu 4).")
        return
    phi = (p - 1) * (q - 1)
    try:
        d = pow(e, -1, phi)
    except ValueError:
        print("[!] e tidak invertible terhadap phi(N). Cek ulang p, q, e.")
        return
    state["d"] = d
    print(f"[+] d = {d}")


def show_pem():
    N, e, d, p, q = state["N"], state["e"], state["d"], state["p"], state["q"]
    if not all([N, e, d, p, q]):
        print("[!] Data belum lengkap. Jalankan menu 1-5 dulu.")
        return
    if RSA is None:
        print("[!] pycryptodome belum terinstall. pip install pycryptodome")
        return
    key = RSA.construct((N, e, d, p, q))
    pem = key.export_key().decode()
    print("\n" + pem + "\n")
    return pem


def save_pem():
    pem = show_pem()
    if not pem:
        return
    fname = input("Nama file output (mis. server_priv.pem): ").strip()
    if not fname:
        print("[!] Dibatalkan.")
        return
    with open(fname, "w") as f:
        f.write(pem)
    print(f"[+] Disimpan ke {fname}")


def show_state():
    print("\n--- STATE SAAT INI ---")
    for k, v in state.items():
        if isinstance(v, int):
            print(f"{k}: {v} ({v.bit_length()} bit)")
        else:
            print(f"{k}: {v}")
    print()


MENU = """
=== Close Prime RSA Recovery ===
1. Input modulus N
2. Input exponent e
3. Jalankan Fermat factorization (cari p, q)
4. Input manual p, q (kalau sudah tahu / dari factordb)
5. Hitung private exponent d
6. Tampilkan private key PEM
7. Simpan private key PEM ke file
8. Tampilkan state
0. Keluar
"""

def main():
    while True:
        print(MENU)
        choice = input("Pilih menu: ").strip()
        if choice == "1":
            input_modulus()
        elif choice == "2":
            input_exponent()
        elif choice == "3":
            fermat_factorize()
        elif choice == "4":
            input_manual_pq()
        elif choice == "5":
            compute_private_key()
        elif choice == "6":
            show_pem()
        elif choice == "7":
            save_pem()
        elif choice == "8":
            show_state()
        elif choice == "0":
            print("Keluar.")
            sys.exit(0)
        else:
            print("[!] Pilihan tidak valid.")


if __name__ == "__main__":
    main()