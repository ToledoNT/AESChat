#include <gtk/gtk.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define PORT 8080
#define IV_LEN 12
#define TAG_LEN 16
#define MAX_MSG_LEN 1024

static const unsigned char SHARED_KEY[32] = {
    0x7a,0x91,0x23,0x44,0x55,0x66,0x77,0x88,
    0x19,0x2a,0x3b,0x4c,0x5d,0x6e,0x7f,0x80,
    0x90,0xa1,0xb2,0xc3,0xd4,0xe5,0xf6,0x07,
    0x18,0x29,0x3a,0x4b,0x5c,0x6d,0x7e,0x8f
};

GtkWidget *entry_name, *entry_msg, *btn_send, *text_view;
GtkTextBuffer *text_buffer;
int sockfd;
pthread_t recv_thread;

// === HEX ===
void to_hex(const unsigned char *in, size_t len, char *out) {
    const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2*i]   = hex[(in[i] >> 4) & 0xF];
        out[2*i+1] = hex[in[i] & 0xF];
    }
    out[2*len] = '\0';
}

int from_hex(const char *in, unsigned char *out, size_t out_max, size_t *out_len) {
    size_t n = strlen(in);
    if (n % 2 != 0) return 0;
    n /= 2;
    if (n > out_max) return 0;
    for (size_t i = 0; i < n; i++) {
        int v1 = in[2*i] > '9' ? (in[2*i] & ~0x20) - 'A' + 10 : in[2*i] - '0';
        int v2 = in[2*i+1] > '9' ? (in[2*i+1] & ~0x20) - 'A' + 10 : in[2*i+1] - '0';
        out[i] = (v1 << 4) | v2;
    }
    *out_len = n;
    return 1;
}

// === AES-GCM ===
int aes_gcm_encrypt(const unsigned char *plaintext, int plen,
                    const unsigned char *key, unsigned char *iv, int iv_len,
                    unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len, clen = 0;

    int ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) &&
             EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) &&
             EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plen);
    clen = len;

    ok = ok && EVP_EncryptFinal_ex(ctx, ciphertext + clen, &len);
    clen += len;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);

    EVP_CIPHER_CTX_free(ctx);
    return ok ? clen : -1;
}

int aes_gcm_decrypt(const unsigned char *ciphertext, int clen,
                    const unsigned char *key, const unsigned char *iv, int iv_len,
                    const unsigned char *tag, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len, plen = 0;

    int ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) &&
             EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) &&
             EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, clen);
    plen = len;

    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)tag) &&
         EVP_DecryptFinal_ex(ctx, plaintext + plen, &len);
    plen += len;

    EVP_CIPHER_CTX_free(ctx);
    return ok ? plen : -1;
}

// === Receber mensagens ===
void *receive_loop(void *arg) {
    char hex_in[(IV_LEN + MAX_MSG_LEN + TAG_LEN) * 2 + 2];
    unsigned char packet[IV_LEN + MAX_MSG_LEN + TAG_LEN];
    unsigned char plaintext[MAX_MSG_LEN + 1];

    while (1) {
        memset(hex_in, 0, sizeof(hex_in));
        int n = read(sockfd, hex_in, sizeof(hex_in) - 1);
        if (n <= 0) break;
        hex_in[n] = '\0';

        size_t packet_len = 0;
        if (!from_hex(hex_in, packet, sizeof(packet), &packet_len)) continue;
        if (packet_len < IV_LEN + TAG_LEN) continue;

        unsigned char *iv = packet;
        unsigned char *tag = packet + packet_len - TAG_LEN;
        unsigned char *cipher = packet + IV_LEN;
        int clen = (int)(packet_len - IV_LEN - TAG_LEN);

        int plen = aes_gcm_decrypt(cipher, clen, SHARED_KEY, iv, IV_LEN, tag, plaintext);
        if (plen < 0) continue;

        plaintext[plen] = '\0';

        gtk_text_buffer_insert_at_cursor(text_buffer, (char *)plaintext, -1);
        gtk_text_buffer_insert_at_cursor(text_buffer, "\n", -1);
    }
    return NULL;
}

// === Enviar mensagem ===
void send_msg(GtkWidget *widget, gpointer data) {
    const char *msg = gtk_entry_get_text(GTK_ENTRY(entry_msg));
    if (strlen(msg) == 0) return;

    unsigned char iv[IV_LEN];
    RAND_bytes(iv, IV_LEN);
    unsigned char cipher[MAX_MSG_LEN];
    unsigned char tag[TAG_LEN];

    int clen = aes_gcm_encrypt((unsigned char*)msg, strlen(msg), SHARED_KEY, iv, IV_LEN, cipher, tag);
    if (clen < 0) return;

    size_t packet_len = IV_LEN + clen + TAG_LEN;
    unsigned char *packet = malloc(packet_len);
    memcpy(packet, iv, IV_LEN);
    memcpy(packet + IV_LEN, cipher, clen);
    memcpy(packet + IV_LEN + clen, tag, TAG_LEN);

    char *hex = malloc(packet_len * 2 + 1);
    to_hex(packet, packet_len, hex);

    write(sockfd, hex, strlen(hex));

    free(packet);
    free(hex);
    gtk_entry_set_text(GTK_ENTRY(entry_msg), "");
}

// === Conectar ao servidor ===
void connect_server(GtkWidget *widget, gpointer data) {
    const char *name = gtk_entry_get_text(GTK_ENTRY(entry_name));

    struct sockaddr_in servaddr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT);
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0) {
        gtk_text_buffer_insert_at_cursor(text_buffer, "Erro ao conectar.\n", -1);
        return;
    }

    dprintf(sockfd, "%s\n", name);
    pthread_create(&recv_thread, NULL, receive_loop, NULL);
}

// === GUI GTK ===
int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(win), "Chat Seguro");
    gtk_window_set_default_size(GTK_WINDOW(win), 400, 400);
    g_signal_connect(win, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_add(GTK_CONTAINER(win), vbox);

    // Nome
    entry_name = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry_name), "Digite seu nome");
    GtkWidget *btn_connect = gtk_button_new_with_label("Conectar");
    g_signal_connect(btn_connect, "clicked", G_CALLBACK(connect_server), NULL);

    GtkWidget *hbox_top = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_box_pack_start(GTK_BOX(hbox_top), entry_name, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(hbox_top), btn_connect, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(vbox), hbox_top, FALSE, FALSE, 0);

    // Chat
    text_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(text_view), GTK_WRAP_WORD);
    text_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(scroll), text_view);
    gtk_box_pack_start(GTK_BOX(vbox), scroll, TRUE, TRUE, 0);

    // Mensagem
    entry_msg = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry_msg), "Digite sua mensagem");
    btn_send = gtk_button_new_with_label("Enviar");
    g_signal_connect(btn_send, "clicked", G_CALLBACK(send_msg), NULL);

    GtkWidget *hbox_msg = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_box_pack_start(GTK_BOX(hbox_msg), entry_msg, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(hbox_msg), btn_send, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(vbox), hbox_msg, FALSE, FALSE, 0);

    gtk_widget_show_all(win);
    gtk_main();

    return 0;
}