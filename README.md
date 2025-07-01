
# 🛡️ Forgegis - Advanced Encryption Software

## 🚀 Minimal Viable Product (MVP) README

**Forgegis** is a lightweight, cross-platform encryption demo in C featuring:

- ChaCha20 stream cipher (256-bit)
- Simplified X25519-style key exchange
- BLAKE2b-inspired hash function
- Secure random generation (Windows CryptoAPI or /dev/urandom)
- Packed data structures for clean serialization
- Explicit memory zeroing of secrets

### 🔥 Usage Example
```
gcc forgegis.c -o forgegis -Wall
./forgegis
```

This encrypts a hardcoded message, decrypts it, verifies integrity, and demonstrates key derivation + toy key exchange.

### ⚠️ Security Note
> 🚨 This is a demonstration. The cryptographic functions are simplified to illustrate principles and are **not secure for production use**.

---

## 💡 Why "Forgegis"?
- Combines **Forge + Gigabytes + Security** — about forging powerful data protection tools.
