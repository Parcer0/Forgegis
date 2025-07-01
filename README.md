
# 🛡️ Forgegis - Advanced Encryption Software

**Forgegis** is a cross-platform encryption software written in C that demonstrates modern cryptographic design concepts using:
- the **ChaCha20 stream cipher** for high-speed symmetric encryption,
- a simplified **X25519-style key exchange** for establishing shared secrets,
- and a lightweight **BLAKE2b-inspired hash function** for key derivation.

The project showcases how to build a secure encryption system from scratch, focusing on:

✅ Secure random number generation (Windows CryptoAPI or `/dev/urandom`)  
✅ Endian-safe portable data formats  
✅ Memory zeroing to prevent sensitive data leaks  
✅ Explicit packed data structures for predictable serialization  
✅ Toy examples of elliptic curve key exchange and password-based encryption

---

## 🚀 What makes Forgegis unique?
- **Truly cross-platform**: compiles cleanly on Windows (MSVC / MinGW / Clang) and Linux (GCC / Clang).  
- **No external dependencies**: everything written in pure portable C, with careful use of the C standard library and OS-provided secure randomness.
- **Secure engineering practices**: all sensitive ephemeral data is wiped from memory after use; bounds checks prevent integer or heap overflows.

---

## ⚠️ Security disclaimer
> 🚨 **IMPORTANT:**  
> Forgegis is an educational demo.  
> The implementations of X25519 and BLAKE2b here are **simplified placeholders** that illustrate cryptographic ideas but are **not safe for production**.  
> For real-world systems, always use vetted libraries like [libsodium](https://libsodium.gitbook.io/doc/) or [OpenSSL](https://www.openssl.org/).

---

## 💡 Why “Forgegis”?
It stands for **Forge + Gigabytes + Security** — evoking the idea of forging robust, high-speed cryptographic systems that protect your data.
