// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// NIP-060 OP_CHECKSIG_P256 reference signer for ESP32 boards (ESP-IDF v6.1).
//
// Two key sources (menuconfig, "Neurai P-256 signer"):
//   - eFuse (default): the private key lives in an eFuse key block with
//     purpose ECDSA_KEY_P256 and is only used through the ECDSA peripheral
//     (PSA opaque key); the firmware never reads it. ESP32-P4 rev >= v3.0,
//     ESP32-C5, ESP32-H2.
//   - software: a key generated with the TRNG and kept in NVS, used by the
//     PSA software implementation. It gives no hardware protection; it exists
//     to test the flow on boards without the peripheral (ESP32-P4 rev < v3.0,
//     ESP32-S3).
//
// Commands on the console (UART or USB Serial/JTAG):
//
//   info                 chip revision, ESP-IDF version and key source
//   pub                  PUB <33-byte compressed public key, hex>
//   sign <digest>        SIG <r || s, 64 bytes hex>: deterministic (RFC 6979)
//                        ECDSA of the 32-byte digest, normalized to low S
//   genkey <index> BURN  eFuse source with CONFIG_NEURAI_P256_ALLOW_EFUSE_BURN:
//                        generate the key with the TRNG and burn it (irreversible)
//   genkey               software source: create the key in NVS; refused if a
//                        key already exists. The firmware never creates or
//                        replaces a key on its own, and never erases NVS: a key
//                        may already control funds.
//
// The digest is SHA-256 of the NIP-060 message, computed by the host
// (contrib/p256/p256_sign.py, contrib/p256/device_sign.py). The firmware does
// not hash it again.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_chip_info.h"
#include "esp_console.h"
#include "esp_idf_version.h"
#include "esp_random.h"
#include "psa/crypto.h"

#if CONFIG_NEURAI_P256_KEY_EFUSE
#include "esp_efuse.h"
#include "psa_crypto_driver_esp_ecdsa.h"
#include "psa_crypto_driver_esp_ecdsa_contexts.h"
#include "soc/soc_caps.h"
#else
#include "nvs.h"
#include "nvs_flash.h"
#endif

// Group order n and floor(n/2), big-endian.
static const uint8_t N_BE[32] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51};
static const uint8_t HALF_N_BE[32] = {
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8};

#define SIGN_ALG PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256)

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s ", label);
    for (size_t i = 0; i < len; ++i) printf("%02x", data[i]);
    printf("\n");
}

static int parse_hex(const char *hex, uint8_t *out, size_t len)
{
    if (strlen(hex) != 2 * len) return -1;
    for (size_t i = 0; i < len; ++i) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    return 0;
}

#if !CONFIG_NEURAI_P256_KEY_EFUSE || CONFIG_NEURAI_P256_ALLOW_EFUSE_BURN
// A private key candidate from the TRNG: 1 <= d < n.
static void random_scalar(uint8_t d[32])
{
    do {
        esp_fill_random(d, 32);
    } while (memcmp(d, N_BE, 32) >= 0 || (d[0] | d[31]) == 0);
}
#endif

#if CONFIG_NEURAI_P256_KEY_EFUSE

static const char *KEY_SOURCE = "efuse";

// ESP32-P4 and ESP32-C5 have one key purpose per curve; the ESP32-H2 has a
// single ECDSA purpose and picks the curve when the key is used.
#if SOC_ECDSA_SUPPORT_CURVE_SPECIFIC_KEY_PURPOSES
#define P256_KEY_PURPOSE ESP_EFUSE_KEY_PURPOSE_ECDSA_KEY_P256
#else
#define P256_KEY_PURPOSE ESP_EFUSE_KEY_PURPOSE_ECDSA_KEY
#endif

static esp_efuse_block_t key_block(void)
{
    return (esp_efuse_block_t)(EFUSE_BLK_KEY0 + CONFIG_NEURAI_P256_EFUSE_KEY_INDEX);
}

// Imports a PSA reference to the eFuse key (the key itself stays in hardware).
static int open_key(psa_key_id_t *id)
{
    if (esp_efuse_get_key_purpose(key_block()) != P256_KEY_PURPOSE) {
        printf("ERR eFuse block KEY%d has no ECDSA_KEY_P256 key\n", CONFIG_NEURAI_P256_EFUSE_KEY_INDEX);
        return -1;
    }
    esp_ecdsa_opaque_key_t opaque = {0};
    opaque.curve = ESP_ECDSA_CURVE_SECP256R1;
    opaque.efuse_block = key_block();
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attr, SIGN_ALG);
    psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_ESP_ECDSA_VOLATILE);
    psa_status_t status = psa_import_key(&attr, (const uint8_t *)&opaque, sizeof(opaque), id);
    psa_reset_key_attributes(&attr);
    if (status != PSA_SUCCESS) {
        printf("ERR psa_import_key %d\n", (int)status);
        return -1;
    }
    return 0;
}

#if CONFIG_NEURAI_P256_ALLOW_EFUSE_BURN
static int cmd_pub(int argc, char **argv);

static int cmd_genkey(int argc, char **argv)
{
    // The whole index argument must be the configured block written in decimal:
    // "4x", "+4" or "04" are refused, not read as 4 the way atoi() would.
    char index[4];
    snprintf(index, sizeof(index), "%d", CONFIG_NEURAI_P256_EFUSE_KEY_INDEX);
    if (argc != 3 || strcmp(argv[2], "BURN") != 0 || strcmp(argv[1], index) != 0) {
        printf("ERR usage: genkey %d BURN  (irreversible; index must match the configured block)\n",
               CONFIG_NEURAI_P256_EFUSE_KEY_INDEX);
        return 1;
    }
    if (!esp_efuse_key_block_unused(key_block())) {
        printf("ERR eFuse block KEY%d is already used\n", CONFIG_NEURAI_P256_EFUSE_KEY_INDEX);
        return 1;
    }
    uint8_t d[32];
    random_scalar(d);
    uint8_t le[32];
    for (int i = 0; i < 32; ++i) le[i] = d[31 - i]; // the eFuse expects little endian
    esp_err_t err = esp_efuse_write_key(key_block(), P256_KEY_PURPOSE, le, sizeof(le));
    memset(d, 0, sizeof(d));
    memset(le, 0, sizeof(le));
    if (err != ESP_OK) {
        printf("ERR esp_efuse_write_key %s\n", esp_err_to_name(err));
        return 1;
    }
    printf("OK key generated in the chip and burned to KEY%d\n", CONFIG_NEURAI_P256_EFUSE_KEY_INDEX);
    return cmd_pub(0, NULL);
}
#endif

#else // CONFIG_NEURAI_P256_KEY_SOFTWARE

static const char *KEY_SOURCE = "software-nvs (no hardware protection)";

// Set by app_main when NVS opened cleanly. NVS is never erased here: if it
// cannot be opened as it is, the key stays untouched and signing is refused.
static bool nvs_ready = false;

// Loads the key from NVS and imports it as a volatile PSA key pair. A missing
// key is an error: only `genkey` creates one.
static int open_key(psa_key_id_t *id)
{
    if (!nvs_ready) {
        printf("ERR NVS is not available; the stored key was left untouched\n");
        return -1;
    }
    nvs_handle_t nvs;
    if (nvs_open("neurai_p256", NVS_READONLY, &nvs) != ESP_OK) {
        printf("ERR no key in NVS: run genkey\n");
        return -1;
    }
    uint8_t d[32];
    size_t len = sizeof(d);
    esp_err_t err = nvs_get_blob(nvs, "priv", d, &len);
    nvs_close(nvs);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        printf("ERR no key in NVS: run genkey\n");
        return -1;
    }
    if (err != ESP_OK || len != sizeof(d)) {
        printf("ERR nvs key %s\n", esp_err_to_name(err));
        return -1;
    }
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attr, SIGN_ALG);
    psa_status_t status = psa_import_key(&attr, d, sizeof(d), id);
    psa_reset_key_attributes(&attr);
    memset(d, 0, sizeof(d));
    if (status != PSA_SUCCESS) {
        printf("ERR psa_import_key %d\n", (int)status);
        return -1;
    }
    return 0;
}

static int cmd_pub(int argc, char **argv);

// Creates the software key with the TRNG; refuses to replace an existing one.
static int cmd_genkey(int argc, char **argv)
{
    (void)argv;
    if (argc != 1) {
        printf("ERR usage: genkey\n");
        return 1;
    }
    if (!nvs_ready) {
        printf("ERR NVS is not available\n");
        return 1;
    }
    nvs_handle_t nvs;
    if (nvs_open("neurai_p256", NVS_READWRITE, &nvs) != ESP_OK) {
        printf("ERR nvs_open\n");
        return 1;
    }
    uint8_t d[32];
    size_t len = sizeof(d);
    if (nvs_get_blob(nvs, "priv", d, &len) != ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        memset(d, 0, sizeof(d));
        printf("ERR a key already exists; it is never replaced\n");
        return 1;
    }
    random_scalar(d);
    esp_err_t err = nvs_set_blob(nvs, "priv", d, sizeof(d));
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    memset(d, 0, sizeof(d));
    if (err != ESP_OK) {
        printf("ERR nvs_set_blob %s\n", esp_err_to_name(err));
        return 1;
    }
    printf("OK key created in NVS\n");
    return cmd_pub(0, NULL);
}

#endif

static int cmd_info(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    esp_chip_info_t chip;
    esp_chip_info(&chip);
    printf("INFO chip=%s rev=v%d.%d idf=%s key=%s\n", CONFIG_IDF_TARGET, chip.revision / 100, chip.revision % 100,
           esp_get_idf_version(), KEY_SOURCE);
    return 0;
}

static int cmd_pub(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    psa_key_id_t id = 0;
    if (open_key(&id) != 0) return 1;
    uint8_t point[65];
    size_t len = 0;
    psa_status_t status = psa_export_public_key(id, point, sizeof(point), &len);
    psa_destroy_key(id);
    if (status != PSA_SUCCESS || len != 65 || point[0] != 0x04) {
        printf("ERR psa_export_public_key %d len %u\n", (int)status, (unsigned)len);
        return 1;
    }
    uint8_t compressed[33];
    compressed[0] = 0x02 | (point[64] & 1);
    memcpy(compressed + 1, point + 1, 32);
    print_hex("PUB", compressed, sizeof(compressed));
    return 0;
}

// s = n - s when s > n/2 (big-endian), so the signature has low S.
static void normalize_low_s(uint8_t s[32])
{
    if (memcmp(s, HALF_N_BE, 32) <= 0) return;
    int borrow = 0;
    for (int i = 31; i >= 0; --i) {
        int v = (int)N_BE[i] - (int)s[i] - borrow;
        borrow = v < 0;
        s[i] = (uint8_t)(v + (borrow ? 256 : 0));
    }
}

static int cmd_sign(int argc, char **argv)
{
    uint8_t digest[32];
    if (argc != 2 || parse_hex(argv[1], digest, sizeof(digest)) != 0) {
        printf("ERR usage: sign <32-byte digest, hex>\n");
        return 1;
    }
    psa_key_id_t id = 0;
    if (open_key(&id) != 0) return 1;
    uint8_t sig[64];
    size_t len = 0;
    psa_status_t status = psa_sign_hash(id, SIGN_ALG, digest, sizeof(digest), sig, sizeof(sig), &len);
    psa_destroy_key(id);
    if (status != PSA_SUCCESS || len != 64) {
        printf("ERR psa_sign_hash %d len %u\n", (int)status, (unsigned)len);
        return 1;
    }
    normalize_low_s(sig + 32);
    print_hex("SIG", sig, sizeof(sig));
    return 0;
}

void app_main(void)
{
#if !CONFIG_NEURAI_P256_KEY_EFUSE
    // Never erase NVS to recover from an error: it holds the key, which may
    // control funds. Erasing is a deliberate maintenance step
    // (`idf.py erase-flash`), not something the firmware decides.
    esp_err_t err = nvs_flash_init();
    nvs_ready = err == ESP_OK;
    if (!nvs_ready) {
        printf("ERR nvs_flash_init %s: the key is kept and signing is disabled\n", esp_err_to_name(err));
    }
#endif
    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("ERR psa_crypto_init\n");
        return;
    }
    esp_console_repl_t *repl = NULL;
    esp_console_repl_config_t repl_config = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
    repl_config.prompt = "p256>";
    const esp_console_cmd_t commands[] = {
        {.command = "info", .help = "Chip revision, ESP-IDF version and key source", .func = cmd_info},
        {.command = "pub", .help = "Compressed P-256 public key", .func = cmd_pub},
        {.command = "sign", .help = "Sign a 32-byte digest (hex), deterministic and low S", .hint = "<digest>",
         .func = cmd_sign},
#if CONFIG_NEURAI_P256_KEY_EFUSE && CONFIG_NEURAI_P256_ALLOW_EFUSE_BURN
        {.command = "genkey", .help = "Generate the key in the chip and burn it (IRREVERSIBLE)",
         .hint = "<index> BURN", .func = cmd_genkey},
#elif !CONFIG_NEURAI_P256_KEY_EFUSE
        {.command = "genkey", .help = "Create the software key in NVS (refused if one exists)", .func = cmd_genkey},
#endif
    };
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); ++i) {
        ESP_ERROR_CHECK(esp_console_cmd_register(&commands[i]));
    }
    ESP_ERROR_CHECK(esp_console_register_help_command());
    ESP_ERROR_CHECK(esp_console_new_repl_stdio(&repl_config, &repl));
    ESP_ERROR_CHECK(esp_console_start_repl(repl));
}
