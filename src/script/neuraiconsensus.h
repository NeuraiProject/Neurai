// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_NEURAICONSENSUS_H
#define NEURAI_NEURAICONSENSUS_H

#include <stdint.h>

#if defined(BUILD_NEURAI_INTERNAL) && defined(HAVE_CONFIG_H)
#include "config/neurai-config.h"
  #if defined(_WIN32)
    #if defined(DLL_EXPORT)
      #if defined(HAVE_FUNC_ATTRIBUTE_DLLEXPORT)
        #define EXPORT_SYMBOL __declspec(dllexport)
      #else
        #define EXPORT_SYMBOL
      #endif
    #endif
  #elif defined(HAVE_FUNC_ATTRIBUTE_VISIBILITY)
    #define EXPORT_SYMBOL __attribute__ ((visibility ("default")))
  #endif
#elif defined(MSC_VER) && !defined(STATIC_LIBNEURAICONSENSUS)
  #define EXPORT_SYMBOL __declspec(dllimport)
#endif

#ifndef EXPORT_SYMBOL
  #define EXPORT_SYMBOL
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define NEURAICONSENSUS_API_VER 1

typedef enum neuraiconsensus_error_t
{
    neuraiconsensus_ERR_OK = 0,
    neuraiconsensus_ERR_TX_INDEX,
    neuraiconsensus_ERR_TX_SIZE_MISMATCH,
    neuraiconsensus_ERR_TX_DESERIALIZE,
    neuraiconsensus_ERR_AMOUNT_REQUIRED,
    neuraiconsensus_ERR_INVALID_FLAGS,
} neuraiconsensus_error;

/** Script verification flags */
enum
{
    neuraiconsensus_SCRIPT_FLAGS_VERIFY_NONE                = 0,
    neuraiconsensus_SCRIPT_FLAGS_VERIFY_P2SH                = (1U << 0), // evaluate P2SH (BIP16) subscripts
    neuraiconsensus_SCRIPT_FLAGS_VERIFY_DERSIG              = (1U << 2), // enforce strict DER (BIP66) compliance
    neuraiconsensus_SCRIPT_FLAGS_VERIFY_NULLDUMMY           = (1U << 4), // enforce NULLDUMMY (BIP147)
    neuraiconsensus_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 9), // enable CHECKLOCKTIMEVERIFY (BIP65)
    neuraiconsensus_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY = (1U << 10), // enable CHECKSEQUENCEVERIFY (BIP112)
    neuraiconsensus_SCRIPT_FLAGS_VERIFY_WITNESS             = (1U << 11), // enable WITNESS (BIP141)
    neuraiconsensus_SCRIPT_FLAGS_VERIFY_CAT                  = (1U << 17), // enable OP_CAT
    neuraiconsensus_SCRIPT_FLAGS_VERIFY_CHECKTEMPLATEVERIFY   = (1U << 18), // enable OP_CHECKTEMPLATEVERIFY
    neuraiconsensus_SCRIPT_FLAGS_VERIFY_CHECKSIGFROMSTACK     = (1U << 19), // enable OP_CHECKSIGFROMSTACK
    neuraiconsensus_SCRIPT_FLAGS_VERIFY_TXHASH               = (1U << 20), // enable OP_TXHASH
    neuraiconsensus_SCRIPT_FLAGS_VERIFY_OUTPUTVALUE          = (1U << 24), // enable OP_OUTPUTVALUE
    neuraiconsensus_SCRIPT_FLAGS_VERIFY_TXLOCKTIME           = (1U << 25), // enable OP_TXLOCKTIME
    neuraiconsensus_SCRIPT_FLAGS_VERIFY_OUTPUTSCRIPT         = (1U << 26), // enable OP_OUTPUTSCRIPT
    neuraiconsensus_SCRIPT_FLAGS_VERIFY_OUTPUTASSETFIELD     = (1U << 27), // enable OP_OUTPUTASSETFIELD
    neuraiconsensus_SCRIPT_FLAGS_VERIFY_64BIT_INTEGERS       = (1U << 28), // enable 64-bit arithmetic + OP_MUL/OP_DIV/OP_MOD
    neuraiconsensus_SCRIPT_FLAGS_VERIFY_INPUTASSETFIELD      = (1U << 29), // enable OP_INPUTASSETFIELD
    neuraiconsensus_SCRIPT_FLAGS_VERIFY_INPUTOUTPUTCOUNT    = (1U << 30), // enable OP_INPUTCOUNT / OP_OUTPUTCOUNT
    neuraiconsensus_SCRIPT_FLAGS_VERIFY_ALL                 = neuraiconsensus_SCRIPT_FLAGS_VERIFY_P2SH | neuraiconsensus_SCRIPT_FLAGS_VERIFY_DERSIG |
                                                               neuraiconsensus_SCRIPT_FLAGS_VERIFY_NULLDUMMY | neuraiconsensus_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY |
                                                               neuraiconsensus_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY | neuraiconsensus_SCRIPT_FLAGS_VERIFY_WITNESS |
                                                               neuraiconsensus_SCRIPT_FLAGS_VERIFY_CAT | neuraiconsensus_SCRIPT_FLAGS_VERIFY_CHECKTEMPLATEVERIFY |
                                                               neuraiconsensus_SCRIPT_FLAGS_VERIFY_CHECKSIGFROMSTACK | neuraiconsensus_SCRIPT_FLAGS_VERIFY_TXHASH |
                                                               neuraiconsensus_SCRIPT_FLAGS_VERIFY_OUTPUTVALUE |
                                                               neuraiconsensus_SCRIPT_FLAGS_VERIFY_TXLOCKTIME |
                                                               neuraiconsensus_SCRIPT_FLAGS_VERIFY_OUTPUTSCRIPT |
                                                               neuraiconsensus_SCRIPT_FLAGS_VERIFY_OUTPUTASSETFIELD |
                                                               neuraiconsensus_SCRIPT_FLAGS_VERIFY_64BIT_INTEGERS |
                                                               neuraiconsensus_SCRIPT_FLAGS_VERIFY_INPUTASSETFIELD |
                                                               neuraiconsensus_SCRIPT_FLAGS_VERIFY_INPUTOUTPUTCOUNT
};

/// Returns 1 if the input nIn of the serialized transaction pointed to by
/// txTo correctly spends the scriptPubKey pointed to by scriptPubKey under
/// the additional constraints specified by flags.
/// If not nullptr, err will contain an error/success code for the operation
EXPORT_SYMBOL int neuraiconsensus_verify_script(const unsigned char *scriptPubKey, unsigned int scriptPubKeyLen,
                                                 const unsigned char *txTo        , unsigned int txToLen,
                                                 unsigned int nIn, unsigned int flags, neuraiconsensus_error* err);

EXPORT_SYMBOL int neuraiconsensus_verify_script_with_amount(const unsigned char *scriptPubKey, unsigned int scriptPubKeyLen, int64_t amount,
                                    const unsigned char *txTo        , unsigned int txToLen,
                                    unsigned int nIn, unsigned int flags, neuraiconsensus_error* err);

EXPORT_SYMBOL unsigned int neuraiconsensus_version();

#ifdef __cplusplus
} // extern "C"
#endif

#undef EXPORT_SYMBOL

#endif // NEURAI_NEURAICONSENSUS_H
