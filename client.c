#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define MAX_NAME_LEN 50
#define MAX_MSG_LEN 1024
#define PORT 8080
#define IV_LEN 12
#define TAG_LEN 16

// ======= CHAVE DEMO (32 bytes). TROQUE EM PRODUÇÃO! =======
static const unsigned char SHARED_KEY[32] = {
    0x7a,0x91,0x23,0x44,0x55,0x66,0x77,0x88,
    0x19,0x2a,0x3b,0x4c,0x5d,0x6e,0x7f,0x80,
    0x90,0xa1,0xb2,0xc3,0xd4,0xe5,0xf6,0x07,
    0x18,0x29,0x3a,0x4b,0x5c,0x6d,0x7e,0x8f
};

// ---- util: HEX encode/decode ----
static void to_hex(const unsigned char *in, size_t len, char *out) {
    static const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2*i]   = hex[(in[i] >> 4) & 0xF];
        out[2*i+1] = hex[in[i] & 0xF];
    }
    out[2*len] = '\0';
}

static int from_hex(const char *in, unsigned char *out, size_t out_max, size_t *out_len) {
    size_t n = strlen(in);
    if (n % 2 != 0) return 0;
    n /= 2;
    if (n > out_max) return 0;
    for (size_t i = 0; i < n; i++) {
        char c1 = in[2*i], c2 = in[2*i+1];
        int v1 = (c1 >= '0' && c1 <= '9') ? c1 - '0' :
                 (c1 >= 'a' && c1 <= 'f') ? c1 - 'a' + 10 :
                 (c1 >= 'A' && c1 <= 'F') ? c1 - 'A' + 10 : -1;
        int v2 = (c2 >= '0' && c2 <= '9') ? c2 - '0' :
                 (c2 >= 'a' && c2 <= 'f') ? c2 - 'a' + 10 :
                 (c2 >= 'A' && c2 <= 'F') ? c2 - 'A' + 10 : -1;
        if (v1 < 0 || v2 < 0) return 0;
        out[i] = (unsigned char)((v1 << 4) | v2);
    }
    *out_len = n;
    return 1;
}

// ---- crypto: AES-256-GCM ----
static int aes_gcm_encrypt(const unsigned char *plaintext, int plen,
                           const unsigned char *key,
                           unsigned char *iv, int iv_len,
                           unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0, clen = 0;
    int ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1
          && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) == 1
          && EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) == 1
          && EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plen) == 1;
    clen = len;
    ok = ok && EVP_EncryptFinal_ex(ctx, ciphertext + clen, &len) == 1;
    clen += len;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) == 1;

    EVP_CIPHER_CTX_free(ctx);
    return ok ? clen : -1;
}

static int aes_gcm_decrypt(const unsigned char *ciphertext, int clen,
                           const unsigned char *key,
                           const unsigned char *iv, int iv_len,
                           const unsigned char *tag,
                           unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0, plen = 0;
    int ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1
          && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) == 1
          && EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) == 1
          && EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, clen) == 1;
    plen = len;

    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)tag) == 1
           && EVP_DecryptFinal_ex(ctx, plaintext + plen, &len) == 1;
    plen += len;

    EVP_CIPHER_CTX_free(ctx);
    return ok ? plen : -1;
}

void *receive_messages(void *sockfd_ptr) {
    int sockfd = *(int *)sockfd_ptr;
    char hex_in[(IV_LEN + MAX_MSG_LEN + TAG_LEN) * 2 + 2];
    unsigned char packet[IV_LEN + MAX_MSG_LEN + TAG_LEN];
    unsigned char plaintext[MAX_MSG_LEN + 1];

    while (1) {
        memset(hex_in, 0, sizeof(hex_in));
        int n = read(sockfd, hex_in, sizeof(hex_in) - 1);
        if (n <= 0) { printf("\nServidor desconectado\n"); break; }
        hex_in[n] = '\0';

        // decodifica e decripta
        size_t packet_len = 0;
        if (!from_hex(hex_in, packet, sizeof(packet), &packet_len)) {
            // pode ser mensagem de boas-vindas em texto puro
            printf("\n%s\nDigite a mensagem: ", hex_in);
            fflush(stdout);
            continue;
        }
        if (packet_len < IV_LEN + TAG_LEN) continue;

        unsigned char *iv = packet;
        unsigned char *tag = packet + packet_len - TAG_LEN;
        unsigned char *cipher = packet + IV_LEN;
        int clen = (int)(packet_len - IV_LEN - TAG_LEN);

        int plen = aes_gcm_decrypt(cipher, clen, SHARED_KEY, iv, IV_LEN, tag, plaintext);
        if (plen < 0) {
            // se falhar, tenta imprimir bruto (pode ser texto do servidor)
            printf("\n[falha decript] %s\nDigite a mensagem: ", hex_in);
            fflush(stdout);
            continue;
        }
        plaintext[plen] = '\0';
        printf("\n%s\nDigite a mensagem: ", plaintext);
        fflush(stdout);
    }
    return NULL;
}

int main() {
    int sockfd;
    struct sockaddr_in servaddr;
    pthread_t tid;
    char name[MAX_NAME_LEN];

    printf("Digite seu nome: ");
    if (!fgets(name, sizeof(name), stdin)) return 0;
    name[strcspn(name, "\n")] = '\0';

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Falha na criação do socket");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(PORT);

    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0) {
        perror("Falha na conexão");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    printf("Conectado ao servidor!\n");

    // envia nome em texto (simples)
    dprintf(sockfd, "%s\n", name);

    if (pthread_create(&tid, NULL, receive_messages, &sockfd) != 0) {
        perror("Falha ao criar thread");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    pthread_detach(tid);

    char buff[MAX_MSG_LEN];
    while (1) {
        printf("Digite a mensagem: ");
        if (!fgets(buff, sizeof(buff), stdin)) break;
        buff[strcspn(buff, "\n")] = '\0';
        if (strlen(buff) == 0) continue;

        if (strncmp(buff, "exit", 4) == 0) {
            // ainda enviamos "exit" criptografado pra o servidor encerrar
            // (poderia enviar em texto puro também)
        }

        // criptografa
        unsigned char iv[IV_LEN];
        if (RAND_bytes(iv, IV_LEN) != 1) { perror("RAND_bytes"); break; }

        unsigned char cipher[MAX_MSG_LEN + TAG_LEN]; // espaço para cipher
        unsigned char tag[TAG_LEN];
        int clen = aes_gcm_encrypt((unsigned char*)buff, (int)strlen(buff),
                                   SHARED_KEY, iv, IV_LEN, cipher, tag);
        if (clen < 0) { fprintf(stderr, "Falha ao criptografar\n"); continue; }

        // monta pacote [IV | CIPHER | TAG] e envia em HEX
        size_t packet_len = IV_LEN + (size_t)clen + TAG_LEN;
        unsigned char *packet = malloc(packet_len);
        if (!packet) continue;
        memcpy(packet, iv, IV_LEN);
        memcpy(packet + IV_LEN, cipher, clen);
        memcpy(packet + IV_LEN + clen, tag, TAG_LEN);

        // HEX
        char *hex_out = malloc(packet_len * 2 + 1);
        if (!hex_out) { free(packet); continue; }
        to_hex(packet, packet_len, hex_out);

        write(sockfd, hex_out, strlen(hex_out));

        free(packet);
        free(hex_out);

        if (strncmp(buff, "exit", 4) == 0) {
            printf("Saindo...\n");
            break;
        }
    }

    close(sockfd);
    return 0;
}