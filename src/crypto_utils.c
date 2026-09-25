/* SHA-256, ECDSA, and password-auth helpers used by the ledger. */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <termios.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "crypto_utils.h"

/* Return a hex-encoded SHA-256 digest for the supplied data. */
int sha256_hex(const void *data, size_t len, char out_hex[HASH_HEX_LEN])
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int  dlen = 0;
    EVP_MD_CTX   *ctx  = NULL;

    if (data == NULL || out_hex == NULL) return ERR_CRYPTO;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) return ERR_CRYPTO;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, data, len)            != 1 ||
        EVP_DigestFinal_ex(ctx, digest, &dlen)      != 1) {
        EVP_MD_CTX_free(ctx);
        return ERR_CRYPTO;
    }
    EVP_MD_CTX_free(ctx);

    bytes_to_hex(digest, dlen, out_hex);
    return OK;
}

/* Convert raw bytes to and from lowercase hexadecimal form. */
void bytes_to_hex(const unsigned char *in, size_t len, char *out_hex)
{
    static const char *H = "0123456789abcdef";
    size_t i;
    for (i = 0; i < len; i++) {
        out_hex[i * 2]     = H[(in[i] >> 4) & 0x0F];
        out_hex[i * 2 + 1] = H[ in[i]       & 0x0F];
    }
    out_hex[len * 2] = '\0';
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int hex_to_bytes(const char *hex, unsigned char *out, size_t max_out,
                 size_t *out_len)
{
    size_t n, i;
    if (hex == NULL || out == NULL) return ERR_CRYPTO;

    n = strlen(hex);
    if (n % 2 != 0 || n / 2 > max_out) return ERR_BAD_FORMAT;

    for (i = 0; i < n; i += 2) {
        int hi = hexval(hex[i]);
        int lo = hexval(hex[i + 1]);
        if (hi < 0 || lo < 0) return ERR_BAD_FORMAT;
        out[i / 2] = (unsigned char)((hi << 4) | lo);
    }
    if (out_len) *out_len = n / 2;
    return OK;
}

/* Create and persist the librarian's P-256 key pair. */
static EVP_PKEY *generate_ec_key(void)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY     *key  = NULL;

    if (pctx == NULL) return NULL;

    if (EVP_PKEY_keygen_init(pctx) != 1 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) != 1 ||
        EVP_PKEY_keygen(pctx, &key) != 1) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(pctx);
    return key;
}

static int save_keys(EVP_PKEY *key)
{
    FILE *fp = NULL;

    if (mkdir(KEY_DIR, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "ERROR: cannot create directory '%s': %s\n",
                KEY_DIR, strerror(errno));
        return ERR_FILE_MISSING;
    }

    fp = fopen(PRIV_KEY_FILE, "w");
    if (fp == NULL) {
        fprintf(stderr, "ERROR: cannot write %s\n", PRIV_KEY_FILE);
        return ERR_FILE_MISSING;
    }
    if (PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL) != 1) {
        fclose(fp);
        return ERR_CRYPTO;
    }
    fclose(fp);
    chmod(PRIV_KEY_FILE, S_IRUSR | S_IWUSR);   /* 0600 - owner only */

    fp = fopen(PUB_KEY_FILE, "w");
    if (fp == NULL) return ERR_FILE_MISSING;
    if (PEM_write_PUBKEY(fp, key) != 1) {
        fclose(fp);
        return ERR_CRYPTO;
    }
    fclose(fp);
    chmod(PUB_KEY_FILE, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH); /* 0644 */
    return OK;
}

EVP_PKEY *crypto_load_or_generate_keys(void)
{
    FILE     *fp  = NULL;
    EVP_PKEY *key = NULL;

    fp = fopen(PRIV_KEY_FILE, "r");
    if (fp != NULL) {                       /* existing key pair */
        key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
        fclose(fp);
        if (key == NULL)
            fprintf(stderr,
                    "ERROR: %s exists but could not be parsed.\n"
                    "       Delete the keys/ folder to regenerate.\n",
                    PRIV_KEY_FILE);
        else
            printf("[crypto] Librarian ECDSA key pair loaded from %s\n",
                   PRIV_KEY_FILE);
        return key;
    }

    printf("[crypto] No key pair found - generating a new ECDSA P-256 "
           "key pair...\n");
    key = generate_ec_key();
    if (key == NULL) {
        fprintf(stderr, "ERROR: ECDSA key generation failed.\n");
        return NULL;
    }
    if (save_keys(key) != OK) {
        fprintf(stderr, "ERROR: could not persist the key pair.\n");
        EVP_PKEY_free(key);
        return NULL;
    }
    printf("[crypto] Key pair created: %s (0600) and %s (0644)\n",
           PRIV_KEY_FILE, PUB_KEY_FILE);
    return key;
}

/* Sign a blob and verify that the signature matches the data. */
int crypto_sign(EVP_PKEY *key, const unsigned char *data, size_t len,
                unsigned char *sig_out, size_t *sig_len_out)
{
    EVP_MD_CTX *ctx = NULL;
    size_t      need = 0;
    unsigned char tmp[128];

    if (key == NULL || data == NULL || sig_out == NULL) return ERR_CRYPTO;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) return ERR_CRYPTO;

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key) != 1 ||
        EVP_DigestSign(ctx, NULL, &need, data, len) != 1 ||
        need > sizeof(tmp)) {
        EVP_MD_CTX_free(ctx);
        return ERR_CRYPTO;
    }
    if (EVP_DigestSign(ctx, tmp, &need, data, len) != 1) {
        EVP_MD_CTX_free(ctx);
        return ERR_CRYPTO;
    }
    EVP_MD_CTX_free(ctx);

    if (need > SIG_MAX_LEN) return ERR_CRYPTO;   /* will not happen for P-256 */

    memcpy(sig_out, tmp, need);
    if (sig_len_out) *sig_len_out = need;
    return OK;
}

int crypto_verify(EVP_PKEY *key, const unsigned char *data, size_t len,
                  const unsigned char *sig, size_t sig_len)
{
    EVP_MD_CTX *ctx = NULL;
    int rc;

    if (key == NULL || data == NULL || sig == NULL || sig_len == 0)
        return ERR_CRYPTO;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) return ERR_CRYPTO;

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, key) != 1) {
        EVP_MD_CTX_free(ctx);
        return ERR_CRYPTO;
    }
    rc = EVP_DigestVerify(ctx, sig, sig_len, data, len);
    EVP_MD_CTX_free(ctx);

    return (rc == 1) ? 1 : 0;
}

/* Compute the salted password hash used for local auth checks. */
static void hash_password(const char *salt_hex, const char *password,
                          char out_hex[HASH_HEX_LEN])
{
    char buf[256];
    snprintf(buf, sizeof(buf), "%s%s", salt_hex, password);
    sha256_hex(buf, strlen(buf), out_hex);
}

int auth_bootstrap(void)
{
    FILE         *fp;
    unsigned char salt[16];
    char          salt_hex[33], hash_hex[HASH_HEX_LEN];

    fp = fopen(AUTH_FILE, "r");
    if (fp != NULL) { fclose(fp); return OK; }      /* already provisioned */

    if (RAND_bytes(salt, sizeof(salt)) != 1) return ERR_CRYPTO;
    bytes_to_hex(salt, sizeof(salt), salt_hex);
    hash_password(salt_hex, "library123", hash_hex);

    fp = fopen(AUTH_FILE, "w");
    if (fp == NULL) {
        fprintf(stderr, "ERROR: cannot create %s\n", AUTH_FILE);
        return ERR_FILE_MISSING;
    }
    fprintf(fp, "# username:salt:sha256(salt+password):role\n");
    fprintf(fp, "librarian:%s:%s:LIBRARIAN\n", salt_hex, hash_hex);

    if (RAND_bytes(salt, sizeof(salt)) != 1) { fclose(fp); return ERR_CRYPTO; }
    bytes_to_hex(salt, sizeof(salt), salt_hex);
    hash_password(salt_hex, "view123", hash_hex);
    fprintf(fp, "viewer:%s:%s:VIEWER\n", salt_hex, hash_hex);

    fclose(fp);
    chmod(AUTH_FILE, S_IRUSR | S_IWUSR);

    printf("[auth] Created %s with default accounts:\n", AUTH_FILE);
    printf("       librarian / library123   (full access)\n");
    printf("       viewer    / view123      (read-only)\n");
    return OK;
}

/* read a password without echoing it to the terminal */
static void read_password(char *buf, size_t sz)
{
    struct termios old, quiet;
    size_t n;

    if (tcgetattr(STDIN_FILENO, &old) == 0) {
        quiet = old;
        quiet.c_lflag &= ~(tcflag_t)ECHO;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet);
    }
    if (fgets(buf, (int)sz, stdin) == NULL) buf[0] = '\0';
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
    printf("\n");

    n = strlen(buf);
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] = '\0';
}

int auth_login(char *role_out, size_t role_sz, char *user_out, size_t user_sz)
{
    FILE *fp;
    char  line[512], user[64], pass[128];
    int   attempts;

    for (attempts = 0; attempts < 3; attempts++) {
        printf("\nUsername: ");
        if (fgets(user, sizeof(user), stdin) == NULL) return ERR_NOT_FOUND;
        user[strcspn(user, "\r\n")] = '\0';

        printf("Password: ");
        read_password(pass, sizeof(pass));

        fp = fopen(AUTH_FILE, "r");
        if (fp == NULL) {
            fprintf(stderr, "ERROR: %s not found.\n", AUTH_FILE);
            return ERR_FILE_MISSING;
        }

        while (fgets(line, sizeof(line), fp) != NULL) {
            char *u, *salt, *hash, *role, *save = NULL;
            char calc[HASH_HEX_LEN];

            if (line[0] == '#' || line[0] == '\n') continue;
            line[strcspn(line, "\r\n")] = '\0';

            u    = strtok_r(line, ":", &save);
            salt = strtok_r(NULL, ":", &save);
            hash = strtok_r(NULL, ":", &save);
            role = strtok_r(NULL, ":", &save);
            if (!u || !salt || !hash || !role) continue;
            if (strcmp(u, user) != 0) continue;

            hash_password(salt, pass, calc);
            if (strcmp(calc, hash) == 0) {
                fclose(fp);
                snprintf(role_out, role_sz, "%s", role);
                snprintf(user_out, user_sz, "%s", user);
                /* wipe the plaintext password from memory */
                memset(pass, 0, sizeof(pass));
                printf("\nLogin successful. Welcome %s (role: %s)\n",
                       user_out, role_out);
                return OK;
            }
        }
        fclose(fp);
        memset(pass, 0, sizeof(pass));
        printf("ERROR: Invalid username or password (%d attempt(s) left).\n",
               2 - attempts);
    }
    return ERR_NOT_FOUND;
}
