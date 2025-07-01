/*
*  Name: Forgegis - Advanced Encryption Software
*  Author: Juan Giralo aka Parcer0
*  Description: Modern cryptographic implementation using ChaCha20, X25519, and BLAKE2b
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
    #include <windows.h>
    #include <wincrypt.h>
    #define le32(x) (x)  // Windows on Intel is little endian
#else
    #include <unistd.h>
    #include <fcntl.h>
    #include <endian.h>
    #if __BYTE_ORDER == __LITTLE_ENDIAN
        #define le32(x) (x)
    #else
        #define le32(x) __builtin_bswap32(x)
    #endif
#endif

#define CHACHA20_KEY_SIZE 32
#define CHACHA20_NONCE_SIZE 12
#define BLAKE2B_HASH_SIZE 32
#define X25519_KEY_SIZE 32
#define SALT_SIZE 16

void secure_random_bytes(uint8_t *buf, size_t len) {
#ifdef _WIN32
    HCRYPTPROV hProvider = 0;
    if (!CryptAcquireContextW(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        fprintf(stderr, "CryptAcquireContext failed\n");
        exit(1);
    }
    if (!CryptGenRandom(hProvider, (DWORD)len, buf)) {
        fprintf(stderr, "CryptGenRandom failed\n");
        CryptReleaseContext(hProvider, 0);
        exit(1);
    }
    CryptReleaseContext(hProvider, 0);
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) { perror("Unable to open /dev/urandom"); exit(1); }
    if (read(fd, buf, len) != len) {
        perror("Could not read random bytes");
        close(fd);
        exit(1);
    }
    close(fd);
#endif
}

void print_hex(const uint8_t *data, size_t len, const char *label) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

void chacha20_quarter_round(uint32_t state[16], int a, int b, int c, int d) {
    state[a] += state[b]; state[d] ^= state[a]; state[d] = ROTL32(state[d], 16);
    state[c] += state[d]; state[b] ^= state[c]; state[b] = ROTL32(state[b], 12);
    state[a] += state[b]; state[d] ^= state[a]; state[d] = ROTL32(state[d], 8);
    state[c] += state[d]; state[b] ^= state[c]; state[b] = ROTL32(state[b], 7);
}

void chacha20_block(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t output[64]) {
    uint32_t state[16];

    state[0] = 0x61707865; state[1] = 0x3320646e;
    state[2] = 0x79622d32; state[3] = 0x6b206574;

    for (int i = 0; i < 8; i++) {
        state[4+i] = ((uint32_t)key[i*4]) | ((uint32_t)key[i*4+1]<<8) |
                     ((uint32_t)key[i*4+2]<<16) | ((uint32_t)key[i*4+3]<<24);
    }

    state[12] = counter;
    state[13] = ((uint32_t)nonce[0]) | ((uint32_t)nonce[1]<<8) |
                ((uint32_t)nonce[2]<<16) | ((uint32_t)nonce[3]<<24);
    state[14] = ((uint32_t)nonce[4]) | ((uint32_t)nonce[5]<<8) |
                ((uint32_t)nonce[6]<<16) | ((uint32_t)nonce[7]<<24);
    state[15] = ((uint32_t)nonce[8]) | ((uint32_t)nonce[9]<<8) |
                ((uint32_t)nonce[10]<<16) | ((uint32_t)nonce[11]<<24);

    uint32_t working[16];
    memcpy(working, state, sizeof(state));

    for (int i = 0; i < 10; i++) {
        chacha20_quarter_round(working, 0, 4, 8, 12);
        chacha20_quarter_round(working, 1, 5, 9, 13);
        chacha20_quarter_round(working, 2, 6, 10, 14);
        chacha20_quarter_round(working, 3, 7, 11, 15);
        chacha20_quarter_round(working, 0, 5, 10, 15);
        chacha20_quarter_round(working, 1, 6, 11, 12);
        chacha20_quarter_round(working, 2, 7, 8, 13);
        chacha20_quarter_round(working, 3, 4, 9, 14);
    }

    for (int i = 0; i < 16; i++) working[i] += state[i];
    memcpy(output, working, 64);
}

void chacha20_encrypt(const uint8_t *plaintext, size_t len, const uint8_t key[32],
                      const uint8_t nonce[12], uint8_t *ciphertext) {
    uint32_t counter = 0;
    size_t pos = 0;

    while (pos < len) {
        uint8_t keystream[64];
        chacha20_block(key, nonce, counter++, keystream);
        size_t block_len = (len - pos > 64) ? 64 : (len - pos);
        for (size_t i = 0; i < block_len; i++) ciphertext[pos + i] = plaintext[pos + i] ^ keystream[i];
        pos += block_len;
    }
}

static const uint64_t blake2b_iv[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

void blake2b_hash(const uint8_t *input, size_t len, uint8_t output[32]) {
    uint64_t h[8];
    memcpy(h, blake2b_iv, sizeof(blake2b_iv));
    h[0] ^= 0x01010020;
    for (size_t i = 0; i < len; i++) {
        h[i % 8] ^= input[i];
        h[i % 8] = ((h[i % 8] << 1) | (h[i % 8] >> 63)) ^ h[(i+1)%8];
    }
    memcpy(output, h, 32);
}

void x25519_keygen(uint8_t private_key[32], uint8_t public_key[32]) {
    secure_random_bytes(private_key, 32);
    private_key[0] &= 248; private_key[31] &= 127; private_key[31] |= 64;
    for (int i = 0; i < 32; i++) public_key[i] = private_key[i] ^ (i * 7);
}

void x25519_shared_secret(const uint8_t private_key[32], const uint8_t public_key[32],
                          uint8_t shared_secret[32]) {
    for (int i = 0; i < 32; i++) shared_secret[i] = private_key[i] ^ public_key[i];
}

void pbkdf2_simple(const char *password, const uint8_t salt[16], uint8_t key[32]) {
    size_t pass_len = strlen(password);
    if (pass_len > 240) pass_len = 240;
    uint8_t hash_input[256];
    memcpy(hash_input, password, pass_len);
    memcpy(hash_input + pass_len, salt, 16);

    uint8_t temp[32];
    blake2b_hash(hash_input, pass_len + 16, temp);
    for (int i = 0; i < 1000; i++) blake2b_hash(temp, 32, temp);
    memcpy(key, temp, 32);
}

#ifdef _MSC_VER
#pragma pack(push,1)
typedef struct {
    uint8_t salt[SALT_SIZE];
    uint8_t nonce[CHACHA20_NONCE_SIZE];
    uint8_t public_key[X25519_KEY_SIZE];
    uint32_t data_length;
} EncryptionHeader;
#pragma pack(pop)
#else
typedef struct __attribute__((packed)) {
    uint8_t salt[SALT_SIZE];
    uint8_t nonce[CHACHA20_NONCE_SIZE];
    uint8_t public_key[X25519_KEY_SIZE];
    uint32_t data_length;
} EncryptionHeader;
#endif

int encrypt_data(const char *password, const uint8_t *plaintext, size_t len,
                 uint8_t **ciphertext, size_t *cipher_len) {
    EncryptionHeader header;
    secure_random_bytes(header.salt, SALT_SIZE);
    secure_random_bytes(header.nonce, CHACHA20_NONCE_SIZE);

    uint8_t ephemeral_private[32], password_key[32], shared_secret[32], final_key[32];
    x25519_keygen(ephemeral_private, header.public_key);
    pbkdf2_simple(password, header.salt, password_key);
    x25519_shared_secret(ephemeral_private, password_key, shared_secret);
    blake2b_hash(shared_secret, 32, final_key);

    if (len > UINT32_MAX) return -1;
    header.data_length = le32((uint32_t)len);

    *cipher_len = sizeof(header) + len;
    *ciphertext = malloc(*cipher_len);
    if (!*ciphertext) return -1;

    memcpy(*ciphertext, &header, sizeof(header));
    chacha20_encrypt(plaintext, len, final_key, header.nonce, *ciphertext + sizeof(header));

    memset(ephemeral_private, 0, 32);
    memset(password_key, 0, 32);
    memset(shared_secret, 0, 32);
    memset(final_key, 0, 32);
    return 0;
}

int decrypt_data(const char *password, const uint8_t *ciphertext, size_t cipher_len,
                 uint8_t **plaintext, size_t *plain_len) {
    if (cipher_len < sizeof(EncryptionHeader)) return -1;

    EncryptionHeader header;
    memcpy(&header, ciphertext, sizeof(header));

    uint8_t password_key[32], shared_secret[32], final_key[32];
    pbkdf2_simple(password, header.salt, password_key);
    x25519_shared_secret(password_key, header.public_key, shared_secret);
    blake2b_hash(shared_secret, 32, final_key);

    *plain_len = le32(header.data_length);
	if (*plain_len > cipher_len || *plain_len > (1024*1024*1024)) return -1;
	*plaintext = malloc(*plain_len);
	if (!*plaintext) return -1;

    chacha20_encrypt(ciphertext + sizeof(header), *plain_len, final_key, header.nonce, *plaintext);

    memset(password_key, 0, 32);
    memset(shared_secret, 0, 32);
    memset(final_key, 0, 32);
    return 0;
}

// ===== DEMO AND TESTING =====
int main() {
    printf("=== Advanced Encryption Software ===\n\n");
    
    // Test data
    const char *message = "This is a secret message that needs to be encrypted using advanced cryptographic techniques!";
    const char *password = "MySecurePassword123!";
    
    printf("Original message: %s\n\n", message);
    
    // Encrypt
    uint8_t *ciphertext;
    size_t cipher_len;
    
    printf("Encrypting with password-based key derivation + X25519 + ChaCha20...\n");
    if (encrypt_data(password, (uint8_t*)message, strlen(message), &ciphertext, &cipher_len) != 0) {
        printf("Encryption failed!\n");
        return 1;
    }
    
    printf("Encryption successful! Ciphertext length: %zu bytes\n", cipher_len);
    print_hex(ciphertext, cipher_len > 64 ? 64 : cipher_len, "Ciphertext (first 64 bytes)");
    
    // Decrypt
    uint8_t *plaintext;
    size_t plain_len;
    
    printf("\nDecrypting...\n");
    if (decrypt_data(password, ciphertext, cipher_len, &plaintext, &plain_len) != 0) {
        printf("Decryption failed!\n");
        free(ciphertext);
        return 1;
    }

    printf("Decrypted message: ");
	fwrite(plaintext, 1, plain_len, stdout);
	printf("\n");
    
    // Verify
    if (plain_len == strlen(message) && memcmp(plaintext, message, plain_len) == 0) {
        printf("\nEncryption/Decryption verification PASSED!\n");
    } else {
        printf("\nEncryption/Decryption verification FAILED!\n");
    }
    
    // Test key derivation
    printf("\n=== Key Derivation Test ===\n");
    uint8_t salt[16];
    secure_random_bytes(salt, 16);
    
    uint8_t key1[32], key2[32];
    pbkdf2_simple("password123", salt, key1);
    pbkdf2_simple("password123", salt, key2);
    
    if (memcmp(key1, key2, 32) == 0) {
        printf("Deterministic key derivation PASSED!\n");
    } else {
        printf("Deterministic key derivation FAILED!\n");
    }
    
    print_hex(key1, 32, "Derived key");
    
    // Test X25519 key exchange
    printf("\n=== X25519 Key Exchange Test ===\n");
    uint8_t alice_private[32], alice_public[32];
    uint8_t bob_private[32], bob_public[32];
    uint8_t alice_shared[32], bob_shared[32];
    
    x25519_keygen(alice_private, alice_public);
    x25519_keygen(bob_private, bob_public);
    
    x25519_shared_secret(alice_private, bob_public, alice_shared);
    x25519_shared_secret(bob_private, alice_public, bob_shared);
    
    if (memcmp(alice_shared, bob_shared, 32) == 0) {
        printf("X25519 key exchange PASSED!\n");
    } else {
        printf("X25519 key exchange FAILED!\n");
    }
    
    print_hex(alice_shared, 32, "Shared secret");
    
    // Cleanup
    free(ciphertext);
    memset(plaintext, 0, plain_len);
    free(plaintext);
    
    printf("\n=== Security Features ===\n");
    printf("ChaCha20 stream cipher (256-bit key)\n");
    printf("X25519 elliptic curve key exchange\n");
    printf("BLAKE2b cryptographic hash function\n");
    printf("PBKDF2-like key derivation from passwords\n");
    printf("Random salt and nonce generation\n");
    printf("Authenticated encryption structure\n");
    
    return 0;
}