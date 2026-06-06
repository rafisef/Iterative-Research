#include <openssl/aes.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>

#define AES_BLOCK_SIZE 16

void encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext) {
    AES_KEY encrypt_key;
    AES_set_encrypt_key(key, 128, &encrypt_key);
    AES_cbc_encrypt(plaintext, ciphertext, plaintext_len, &encrypt_key, iv, AES_ENCRYPT);
}

void decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext) {
    AES_KEY decrypt_key;
    AES_set_decrypt_key(key, 128, &decrypt_key);
    AES_cbc_encrypt(ciphertext, plaintext, ciphertext_len, &decrypt_key, iv, AES_DECRYPT);
}

int main() {
    const unsigned char key[] = "0123456789abcdef";
    const unsigned char iv[] = "1234567890123456";

    const unsigned char plaintext[] = "Hello, AES encryption!";

    int plaintext_len = strlen((char *)plaintext);

    unsigned char ciphertext[plaintext_len + AES_BLOCK_SIZE];
    memset(ciphertext, 0, sizeof(ciphertext));

    encrypt(plaintext, plaintext_len, key, iv, ciphertext);

    printf("Encrypted Text: ");
    for (int i = 0; i < plaintext_len + AES_BLOCK_SIZE; ++i) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    unsigned char decrypted_text[plaintext_len + AES_BLOCK_SIZE];
    memset(decrypted_text, 0, sizeof(decrypted_text));

    decrypt(ciphertext, plaintext_len + AES_BLOCK_SIZE, key, iv, decrypted_text);

    printf("Decrypted Text: %s\n", decrypted_text);

    return 0;
}