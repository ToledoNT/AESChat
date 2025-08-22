#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define MAX_CLIENTS 10
#define MAX_NAME_LEN 50
#define MAX_MSG_LEN 1024
#define PORT 8080
#define IV_LEN 12
#define TAG_LEN 16

typedef struct {
    int sockfd;
    char name[MAX_NAME_LEN];
    struct sockaddr_in addr;
} client_t;

client_t *clients[MAX_CLIENTS];
int client_count = 0;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

// ======= CHAVE DEMO (32 bytes) ======= //
static const unsigned char SHARED_KEY[32] = {
    0x7a,0x91,0x23,0x44,0x55,0x66,0x77,0x88,
    0x19,0x2a,0x3b,0x4c,0x5d,0x6e,0x7f,0x80,
    0x90,0xa1,0xb2,0xc3,0xd4,0xe5,0xf6,0x07,
    0x18,0x29,0x3a,0x4b,0x5c,0x6d,0x7e,0x8f
};

// ---- util HEX ----
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

// ---- crypto AES-256-GCM ----
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

// Envio completo de buffer (garante envio total)
static ssize_t write_all(int fd, const void *buf, size_t count) {
    size_t left = count;
    const char *ptr = buf;
    while (left > 0) {
        ssize_t written = write(fd, ptr, left);
        if (written <= 0) return -1;
        left -= written;
        ptr += written;
    }
    return count;
}

// Leitura do nome do cliente, garante leitura até newline ou MAX_NAME_LEN-1
int read_name(int sockfd, char *name, size_t max_len) {
    size_t idx = 0;
    while (idx < max_len - 1) {
        char c;
        ssize_t r = read(sockfd, &c, 1);
        if (r <= 0) return -1;
        if (c == '\n' || c == '\r') break;
        name[idx++] = c;
    }
    name[idx] = '\0';
    return 0;
}

void broadcast_plaintext(const char *name, const char *plaintext, int sender_sockfd) {
    char formatted[MAX_NAME_LEN + MAX_MSG_LEN + 3];
    snprintf(formatted, sizeof(formatted), "%s: %s", name, plaintext);

    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < client_count; i++) {
        if (clients[i]->sockfd == sender_sockfd) continue;

        unsigned char iv[IV_LEN];
        if (RAND_bytes(iv, IV_LEN) != 1) continue;

        unsigned char cipher[MAX_NAME_LEN + MAX_MSG_LEN + TAG_LEN];
        unsigned char tag[TAG_LEN];
        int clen = aes_gcm_encrypt((unsigned char*)formatted, (int)strlen(formatted),
                                   SHARED_KEY, iv, IV_LEN, cipher, tag);
        if (clen < 0) continue;

        size_t packet_len = IV_LEN + (size_t)clen + TAG_LEN;
        unsigned char *packet = malloc(packet_len);
        if (!packet) continue;

        memcpy(packet, iv, IV_LEN);
        memcpy(packet + IV_LEN, cipher, clen);
        memcpy(packet + IV_LEN + clen, tag, TAG_LEN);

        char *hex_out = malloc(packet_len * 2 + 1);
        if (!hex_out) {
            free(packet);
            continue;
        }
        to_hex(packet, packet_len, hex_out);

        // Envio completo com write_all
        if (write_all(clients[i]->sockfd, hex_out, strlen(hex_out)) < 0) {
            perror("Erro ao enviar para cliente");
        }

        free(packet);
        free(hex_out);
    }
    pthread_mutex_unlock(&clients_mutex);
}

void *client_handler(void *arg) {
    client_t *cli = (client_t *)arg;
    char hex_in[(IV_LEN + MAX_MSG_LEN + TAG_LEN) * 2 + 2];
    unsigned char packet[IV_LEN + MAX_MSG_LEN + TAG_LEN];
    unsigned char plaintext[MAX_MSG_LEN + 1];

    // Mensagem de entrada
    {
        char joinmsg[128];
        snprintf(joinmsg, sizeof(joinmsg), "%s entrou no chat.", cli->name);
        printf("%s\n", joinmsg);
        broadcast_plaintext("Servidor", joinmsg, -1);
    }

    int n;
    while ((n = read(cli->sockfd, hex_in, sizeof(hex_in) - 1)) > 0) {
        hex_in[n] = '\0';

        size_t packet_len = 0;
        if (!from_hex(hex_in, packet, sizeof(packet), &packet_len) || packet_len < IV_LEN + TAG_LEN) {
            // Ignorar dados inválidos
            continue;
        }

        unsigned char *iv = packet;
        unsigned char *tag = packet + packet_len - TAG_LEN;
        unsigned char *cipher = packet + IV_LEN;
        int clen = (int)(packet_len - IV_LEN - TAG_LEN);

        int plen = aes_gcm_decrypt(cipher, clen, SHARED_KEY, iv, IV_LEN, tag, plaintext);
        if (plen < 0) {
            fprintf(stderr, "Falha ao decriptar mensagem de %s\n", cli->name);
            continue;
        }
        plaintext[plen] = '\0';

        if (strncmp((char*)plaintext, "exit", 4) == 0) {
            printf("Cliente %s saiu.\n", cli->name);
            char leavemsg[128];
            snprintf(leavemsg, sizeof(leavemsg), "%s saiu do chat.", cli->name);
            broadcast_plaintext("Servidor", leavemsg, -1);
            break;
        }

        printf("%s: %s\n", cli->name, plaintext);
        broadcast_plaintext(cli->name, (char*)plaintext, cli->sockfd);
    }

    close(cli->sockfd);

    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < client_count; i++) {
        if (clients[i]->sockfd == cli->sockfd) {
            for (int j = i; j < client_count - 1; j++)
                clients[j] = clients[j + 1];
            client_count--;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    free(cli);
    return NULL;
}

int main() {
    int sockfd, connfd;
    struct sockaddr_in servaddr, cliaddr;
    socklen_t len;
    pthread_t tid;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Falha na criação do socket");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Erro setsockopt");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0) {
        perror("Falha no bind");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    if (listen(sockfd, MAX_CLIENTS) != 0) {
        perror("Falha no listen");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    printf("Servidor ouvindo na porta %d\n", PORT);

    len = sizeof(cliaddr);
    while (1) {
        connfd = accept(sockfd, (struct sockaddr *)&cliaddr, &len);
        if (connfd < 0) {
            perror("Falha no accept");
            continue;
        }
        printf("Novo cliente conectado: %s\n", inet_ntoa(cliaddr.sin_addr));

        client_t *cli_info = malloc(sizeof(client_t));
        if (!cli_info) {
            perror("Falha na alocação");
            close(connfd);
            continue;
        }

        cli_info->sockfd = connfd;
        cli_info->addr = cliaddr;

        // lê nome (texto puro, até newline ou limite)
        if (read_name(connfd, cli_info->name, MAX_NAME_LEN) < 0) {
            printf("Falha ao receber nome do cliente\n");
            close(connfd);
            free(cli_info);
            continue;
        }

        pthread_mutex_lock(&clients_mutex);
        if (client_count >= MAX_CLIENTS) {
            pthread_mutex_unlock(&clients_mutex);
            printf("Máximo de clientes atingido\n");
            close(connfd);
            free(cli_info);
            continue;
        }
        clients[client_count++] = cli_info;
        pthread_mutex_unlock(&clients_mutex);

        pthread_create(&tid, NULL, &client_handler, (void*)cli_info);
        pthread_detach(tid);
    }

    close(sockfd);
    return 0;
}