#include <gtk/gtk.h>
#include <glib/gunicode.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <getopt.h>
#include "dh.h"
#include "keys.h"
#include "util.h"
#include <time.h>

#define MAX(a, b) ((a) > (b) ? (a) : (b))

// Define global variables
static GtkTextBuffer* tbuf; /* transcript buffer */
static GtkTextBuffer* mbuf; /* message buffer */
static GtkTextView*  tview; /* view for transcript */
static GtkTextMark*  mark;  /* used for scrolling to end of transcript */

static pthread_t trecv;     /* thread to receive incoming messages */
void* recvMsg(void*);       /* function to handle receiving messages */

// Network variables
static int listensock, sockfd;
static int isclient = 1;

void error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

// Initialize server network
int initServerNet(int port) {
    struct sockaddr_in serv_addr;
    listensock = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
    if (listensock < 0) error("ERROR opening socket");
    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    if (bind(listensock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
        error("ERROR on binding");
    listen(listensock, 1);
    socklen_t clilen;
    struct sockaddr_in cli_addr;
    sockfd = accept(listensock, (struct sockaddr *)&cli_addr, &clilen);
    if (sockfd < 0) error("error on accept");
    close(listensock);
    return 0;
}

// Initialize client network
int initClientNet(char* hostname, int port) {
    struct sockaddr_in serv_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct hostent *server;
    if (sockfd < 0) error("ERROR opening socket");
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }
    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    serv_addr.sin_port = htons(port);
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
        error("ERROR connecting");
    return 0;
}

// Shutdown the network connection
int shutdownNetwork() {
    shutdown(sockfd, 2);
    close(sockfd);
    return 0;
}

// Utility function to generate a nonce (timestamp-based)
unsigned long long generateNonce() {
    return (unsigned long long)time(NULL);  // Use the current timestamp as the nonce
}

// Function for RSA signing challenge
int signChallenge(RSA *private_key, unsigned char *challenge, unsigned char *signed_challenge) {
    unsigned int sig_len;
    if (RSA_sign(NID_sha256, challenge, strlen((char *)challenge), signed_challenge, &sig_len, private_key) != 1) {
        fprintf(stderr, "Error signing challenge: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
    return sig_len;
}

// Function for RSA challenge verification
int verifyChallenge(RSA *public_key, unsigned char *challenge, unsigned char *signed_challenge) {
    if (RSA_verify(NID_sha256, challenge, strlen((char *)challenge), signed_challenge, 256, public_key) != 1) {
        fprintf(stderr, "Error verifying challenge: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
    return 0;
}

// AES encryption function
int encryptMessage(unsigned char *message, int message_len, unsigned char *session_key, unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    unsigned char iv[12] = {0};  // Initialize IV to 0 for simplicity
    int len;
    
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, session_key, iv)) {
        return -1;
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, message, message_len)) {
        return -1;
    }

    int ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        return -1;
    }

    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// AES decryption function
int decryptMessage(unsigned char *ciphertext, int ciphertext_len, unsigned char *session_key, unsigned char *tag, unsigned char *decrypted_message) {
    EVP_CIPHER_CTX *ctx;
    unsigned char iv[12] = {0};  // Initialize IV to 0 for simplicity
    int len;
    
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, session_key, iv)) {
        return -1;
    }

    if (1 != EVP_DecryptUpdate(ctx, decrypted_message, &len, ciphertext, ciphertext_len)) {
        return -1;
    }

    int decrypted_len = len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
        return -1;
    }

    if (1 != EVP_DecryptFinal_ex(ctx, decrypted_message + len, &len)) {
        return -1;
    }

    decrypted_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return decrypted_len;
}

// HMAC function for integrity
int generateHMAC(unsigned char *message, int message_len, unsigned char *session_key, unsigned char *mac) {
    unsigned int len;
    HMAC_CTX *ctx = HMAC_CTX_new();

    HMAC_Init_ex(ctx, session_key, strlen((char *)session_key), EVP_sha256(), NULL);
    HMAC_Update(ctx, message, message_len);
    HMAC_Final(ctx, mac, &len);
    HMAC_CTX_free(ctx);
    
    return len;
}

// Verify HMAC for integrity
int verifyHMAC(unsigned char *message, int message_len, unsigned char *session_key, unsigned char *mac) {
    unsigned char computed_mac[32];
    int len = generateHMAC(message, message_len, session_key, computed_mac);
    
    return (memcmp(mac, computed_mac, len) == 0) ? 0 : -1;
}

// Store and check nonces
unsigned long long last_nonce = 0;

// Check for replay
int checkReplay(unsigned long long nonce) {
    if (nonce <= last_nonce) {
        return -1;  // Replay detected
    }
    last_nonce = nonce;
    return 0;  // Valid new message
}

// Main function to initialize and run the chat
int main(int argc, char *argv[]) {
    // Initialize Diffie-Hellman parameters and keys
    if (init("params") != 0) {
        fprintf(stderr, "Could not read DH params from file 'params'\n");
        return 1;
    }

    // Parse command-line options
    static struct option long_opts[] = {
        {"connect", required_argument, 0, 'c'},
        {"listen", no_argument, 0, 'l'},
        {"port", required_argument, 0, 'p'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int c;
    char hostname[HOST_NAME_MAX + 1] = "localhost";
    int port = 1337;
    
    while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, NULL)) != -1) {
        switch (c) {
            case 'c':
                strncpy(hostname, optarg, HOST_NAME_MAX);
                break;
            case 'l':
                isclient = 0;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'h':
                printf("Usage: %s [OPTIONS]...\n", argv[0]);
                return 0;
        }
    }

    // Initialize client or server network
    if (isclient) {
        initClientNet(hostname, port);
    } else {
        initServerNet(port);
    }

    // Generate DH keys for client/server
    dhKey myKey;
    dhGenk(&myKey);

    // Send public key to the other party
    char* publicKeyHex = hashPK(&myKey, NULL);
    ssize_t nbytes = send(sockfd, publicKeyHex, strlen(publicKeyHex), 0);

    // Receive other party's public key
    char otherPublicKey[1024];
    nbytes = recv(sockfd, otherPublicKey, sizeof(otherPublicKey), 0);

    // Compute shared secret and derive session key
    mpz_t sharedSecret;
    mpz_init(sharedSecret);
    mpz_t otherPartyPK;
    mpz_init(otherPartyPK);
    Z2BYTES(otherPartyPK, otherPublicKey, nbytes);
    mpz_powm(sharedSecret, otherPartyPK, myKey.SK, p);  // sharedSecret = otherPartyPK^myKey.SK mod p

    unsigned char sessionKey[EVP_MAX_KEY_LENGTH];
    HKDF(sessionKey, sizeof(sessionKey), EVP_sha256(), sharedSecret, sizeof(sharedSecret), NULL, 0, NULL, 0);

    // Send a nonce to prevent replay attacks
    unsigned long long nonce = generateNonce();
    send(sockfd, &nonce, sizeof(nonce), 0);

    // Set up GTK UI and network communication (your existing GTK code should go here)
    gtk_init(&argc, &argv);

    // Additional UI and network message handling goes here...

    gtk_main();
    shutdownNetwork();
    return 0;
}
