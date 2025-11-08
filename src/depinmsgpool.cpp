// Copyright (c) 2024 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "depinmsgpool.h"
#include "depinmsgpoolnet.h"
#include "validation.h"
#include "assets/assets.h"
#include "assets/assetdb.h"
#include "hash.h"
#include "utiltime.h"
#include "key.h"
#include "pubkey.h"
#include "base58.h"
#include "util.h"
#include "utilstrencodings.h"

#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

std::unique_ptr<CDepinMsgPool> pDepinMsgPool;

// CDepinMessage implementation

uint256 CDepinMessage::GetHash() const {
    CHashWriter ss(SER_GETHASH, 0);
    ss << token << senderAddress << timestamp;
    return ss.GetHash();
}

bool CDepinMessage::IsExpired(int64_t currentTime) const {
    return (currentTime - timestamp) > DEPIN_MESSAGE_EXPIRY_TIME;
}

std::string CDepinMessage::ToString() const {
    return strprintf("CDepinMessage(token=%s, sender=%s, timestamp=%d, recipients=%d)",
                     token, senderAddress, timestamp, encryptedMessages.size());
}

// CDepinMsgPool implementation

CDepinMsgPool::CDepinMsgPool()
    : fEnabled(false), nPort(DEFAULT_DEPIN_MSG_PORT),
      nMaxRecipients(DEFAULT_MAX_DEPIN_RECIPIENTS) {
}

bool CDepinMsgPool::Initialize(const std::string& token, unsigned int port, unsigned int maxRecipients) {
    LOCK(cs_depinmsgpool);

    // Verificar que -assetindex esté activo (OBLIGATORIO)
    if (!fAssetIndex) {
        LogPrintf("ERROR: Chat mempool requires -assetindex to be enabled. "
                  "Please restart with -assetindex and -reindex\n");
        return false;
    }

    // Verificar que el token sea válido
    AssetType type;
    std::string error;
    if (!IsAssetNameValid(token, type, error)) {
        LogPrintf("ERROR: Invalid chat mempool token '%s': %s\n", token, error);
        return false;
    }

    // Verificar que el token existe
    if (!passetsdb) {
        LogPrintf("ERROR: Asset database not available\n");
        return false;
    }

    CNewAsset assetData;
    int nHeight;
    uint256 blockHash;
    if (!passetsdb->ReadAssetData(token, assetData, nHeight, blockHash)) {
        LogPrintf("ERROR: Token '%s' does not exist in blockchain\n", token);
        return false;
    }

    activeToken = token;
    nPort = port;
    nMaxRecipients = std::min(maxRecipients, MAX_DEPIN_RECIPIENTS);
    fEnabled = true;

    LogPrintf("Chat mempool initialized: token=%s, port=%d, maxRecipients=%d\n",
              activeToken, nPort, nMaxRecipients);

    return true;
}

bool CDepinMsgPool::AddMessage(const CDepinMessage& message, std::string& error) {
    LOCK(cs_depinmsgpool);

    if (!fEnabled) {
        error = "Chat mempool is not enabled";
        return false;
    }

    // Verificar que el token coincide
    if (message.token != activeToken) {
        error = strprintf("Message token '%s' does not match active token '%s'",
                         message.token, activeToken);
        return false;
    }

    // Verificar timestamp (no aceptar mensajes del futuro)
    int64_t currentTime = GetTime();
    if (message.timestamp > currentTime + 60) { // +60s de tolerancia
        error = "Message timestamp is too far in the future";
        return false;
    }

    // Verificar que no está expirado
    if (message.IsExpired(currentTime)) {
        error = "Message is already expired";
        return false;
    }

    // Verificar tamaño del mensaje
    size_t totalSize = 0;
    for (const auto& enc : message.encryptedMessages) {
        totalSize += enc.encryptedData.size();
    }
    if (totalSize > MAX_DEPIN_MESSAGE_SIZE * message.encryptedMessages.size()) {
        error = "Message exceeds maximum size";
        return false;
    }

    // Verificar número de destinatarios
    if (message.encryptedMessages.size() > nMaxRecipients) {
        error = strprintf("Too many recipients (%d), maximum is %d",
                         message.encryptedMessages.size(), nMaxRecipients);
        return false;
    }

    // Verificar firma
    if (!VerifyDepinMessageSignature(message)) {
        error = "Invalid message signature";
        return false;
    }

    // Verificar que el remitente posee el token
    if (!CheckTokenOwnership(message.senderAddress, activeToken, error)) {
        return false;
    }

    // Añadir mensaje
    uint256 hash = message.GetHash();

    // Verificar si ya existe
    if (mapMessages.count(hash)) {
        error = "Message already exists in mempool";
        return false;
    }

    mapMessages[hash] = message;
    mapByTime.insert(std::make_pair(message.timestamp, hash));

    LogPrint(BCLog::MEMPOOL, "Chat message added: hash=%s, sender=%s, recipients=%d\n",
             hash.ToString(), message.senderAddress, message.encryptedMessages.size());

    return true;
}

bool CDepinMsgPool::GetDepinMessage(const uint256& hash, CDepinMessage& message) const {
    LOCK(cs_depinmsgpool);
    auto it = mapMessages.find(hash);
    if (it == mapMessages.end())
        return false;
    message = it->second;
    return true;
}

std::vector<CDepinMessage> CDepinMsgPool::GetMessagesForAddress(const std::string& address) const {
    LOCK(cs_depinmsgpool);
    std::vector<CDepinMessage> result;

    for (const auto& entry : mapMessages) {
        const CDepinMessage& msg = entry.second;

        // Buscar si esta dirección es destinataria
        for (const auto& enc : msg.encryptedMessages) {
            if (enc.recipientAddress == address) {
                result.push_back(msg);
                break;
            }
        }
    }

    return result;
}

std::vector<CDepinMessage> CDepinMsgPool::GetAllMessages() const {
    LOCK(cs_depinmsgpool);
    std::vector<CDepinMessage> result;
    for (const auto& entry : mapMessages) {
        result.push_back(entry.second);
    }
    return result;
}

size_t CDepinMsgPool::GetMessageCount() const {
    LOCK(cs_depinmsgpool);
    return mapMessages.size();
}

void CDepinMsgPool::RemoveExpiredMessages(int64_t currentTime) {
    LOCK(cs_depinmsgpool);

    std::vector<uint256> toRemove;

    for (const auto& entry : mapMessages) {
        if (entry.second.IsExpired(currentTime)) {
            toRemove.push_back(entry.first);
        }
    }

    for (const auto& hash : toRemove) {
        auto it = mapMessages.find(hash);
        if (it != mapMessages.end()) {
            int64_t timestamp = it->second.timestamp;
            mapMessages.erase(it);

            // Eliminar de mapByTime
            auto range = mapByTime.equal_range(timestamp);
            for (auto timeIt = range.first; timeIt != range.second; ) {
                if (timeIt->second == hash) {
                    timeIt = mapByTime.erase(timeIt);
                } else {
                    ++timeIt;
                }
            }
        }
    }

    if (!toRemove.empty()) {
        LogPrint(BCLog::MEMPOOL, "Removed %d expired chat messages\n", toRemove.size());
    }
}

void CDepinMsgPool::Clear() {
    LOCK(cs_depinmsgpool);
    mapMessages.clear();
    mapByTime.clear();
    LogPrint(BCLog::MEMPOOL, "Chat mempool cleared\n");
}

size_t CDepinMsgPool::Size() const {
    LOCK(cs_depinmsgpool);
    return mapMessages.size();
}

size_t CDepinMsgPool::DynamicMemoryUsage() const {
    LOCK(cs_depinmsgpool);
    size_t total = 0;
    for (const auto& entry : mapMessages) {
        const CDepinMessage& msg = entry.second;
        total += sizeof(CDepinMessage);
        total += msg.token.size();
        total += msg.senderAddress.size();
        total += msg.signature.size();
        for (const auto& enc : msg.encryptedMessages) {
            total += sizeof(CDepinEncryptedMessage);
            total += enc.recipientAddress.size();
            total += enc.encryptedData.size();
        }
    }
    return total;
}

int64_t CDepinMsgPool::GetOldestMessageTime() const {
    LOCK(cs_depinmsgpool);
    if (mapByTime.empty())
        return 0;
    return mapByTime.begin()->first;
}

int64_t CDepinMsgPool::GetNewestMessageTime() const {
    LOCK(cs_depinmsgpool);
    if (mapByTime.empty())
        return 0;
    return mapByTime.rbegin()->first;
}

// Funciones auxiliares

bool VerifyDepinMessageSignature(const CDepinMessage& message) {
    // TODO: Implementar verificación de firma ECDSA
    // Por ahora retornamos true para permitir desarrollo
    // La implementación completa requiere:
    // 1. Construir el hash del mensaje (token + sender + timestamp + encrypted messages)
    // 2. Recuperar la clave pública desde la dirección del remitente
    // 3. Verificar la firma usando CPubKey::Verify()

    if (message.signature.empty()) {
        return false;
    }

    // Placeholder - en producción debe verificar la firma real
    return true;
}

bool SignDepinMessage(CDepinMessage& message, const std::string& senderAddress) {
#ifdef ENABLE_WALLET
    // TODO: Implementar firma del mensaje
    // Por ahora creamos una firma dummy para permitir desarrollo
    // La implementación completa requiere:
    // 1. Obtener la clave privada del wallet para senderAddress
    // 2. Construir el hash del mensaje
    // 3. Firmar con CKey::Sign()

    // Firma dummy de 65 bytes
    message.signature.resize(65);
    for (size_t i = 0; i < 65; i++) {
        message.signature[i] = static_cast<unsigned char>(i);
    }
    return true;
#else
    return false;
#endif
}

bool CheckTokenOwnership(const std::string& address, const std::string& token, std::string& error) {
    if (!passetsdb) {
        error = "Asset database not available";
        return false;
    }

    CAmount quantity = 0;
    if (!passetsdb->ReadAssetAddressQuantity(token, address, quantity)) {
        error = strprintf("Address '%s' does not own token '%s'", address, token);
        return false;
    }

    if (quantity <= 0) {
        error = strprintf("Address '%s' has zero balance of token '%s'", address, token);
        return false;
    }

    return true;
}

std::vector<std::string> GetTokenHolders(const std::string& token, unsigned int maxHolders, std::string& error) {
    // REQUIERE -assetindex (ya verificado en Initialize)
    if (!fAssetIndex) {
        error = "Asset index is required but not enabled";
        return std::vector<std::string>();
    }

    if (!passetsdb) {
        error = "Asset database not available";
        return std::vector<std::string>();
    }

    std::vector<std::pair<std::string, CAmount>> vecHolders;
    int nTotalEntries = 0;

    // Obtener holders desde el índice
    if (!passetsdb->AssetAddressDir(vecHolders, nTotalEntries, false, token, maxHolders + 1, 0)) {
        error = "Failed to query token holders from asset index";
        return std::vector<std::string>();
    }

    // Verificar límite
    if (nTotalEntries > (int)maxHolders) {
        error = strprintf("Token has %d holders, exceeds maximum of %d. Use a more exclusive token.",
                         nTotalEntries, maxHolders);
        return std::vector<std::string>();
    }

    // Extraer solo direcciones con balance > 0
    std::vector<std::string> addresses;
    for (const auto& holder : vecHolders) {
        if (holder.second > 0) {
            addresses.push_back(holder.first);
        }
    }

    return addresses;
}

bool EncryptMessageForRecipient(const std::string& message, const std::string& recipientAddress,
                                 std::vector<unsigned char>& encryptedData, std::string& error) {
    // TODO: Implementar cifrado ECIES real
    // Por ahora simulamos el cifrado para permitir desarrollo
    // La implementación completa requiere:
    // 1. Obtener la clave pública del recipientAddress
    // 2. Generar un par de claves efímeras
    // 3. Realizar ECDH
    // 4. Derivar clave de cifrado con KDF
    // 5. Cifrar con AES-256-CBC
    // 6. Calcular HMAC-SHA256
    // 7. Empaquetar todo junto

    // Cifrado dummy: simplemente guardamos el mensaje en claro por ahora
    encryptedData.clear();
    encryptedData.insert(encryptedData.end(), message.begin(), message.end());

    return true;
}

bool DecryptMessageForAddress(const std::vector<unsigned char>& encryptedData,
                               const std::string& address, std::string& decryptedMessage,
                               std::string& error) {
#ifdef ENABLE_WALLET
    // TODO: Implementar descifrado ECIES real
    // Por ahora simulamos el descifrado para permitir desarrollo
    // La implementación completa requiere:
    // 1. Obtener la clave privada del wallet para address
    // 2. Extraer la clave pública efímera del paquete
    // 3. Realizar ECDH
    // 4. Derivar clave de descifrado con KDF
    // 5. Verificar HMAC
    // 6. Descifrar con AES-256-CBC

    // Descifrado dummy: asumimos que está en claro
    decryptedMessage = std::string(encryptedData.begin(), encryptedData.end());

    return true;
#else
    error = "Wallet not available for decryption";
    return false;
#endif
}

bool QueryRemoteDepinMsgPool(const std::string& ipAddress, int port,
                            const std::string& token,
                            const std::vector<std::string>& myAddresses,
                            std::vector<CDepinMessage>& messages,
                            std::string& error) {
    LogPrint(BCLog::NET, "QueryRemoteDepinMsgPool: Connecting to %s:%d for token %s\n",
             ipAddress, port, token);

    // Usar el cliente de chat mempool
    bool success = CDepinMsgPoolClient::QueryMessages(ipAddress, port, token,
                                                     myAddresses, messages, error);

    if (success) {
        LogPrint(BCLog::NET, "QueryRemoteDepinMsgPool: Successfully retrieved %d messages\n",
                messages.size());
    } else {
        LogPrint(BCLog::NET, "QueryRemoteDepinMsgPool: Failed: %s\n", error);
    }

    return success;
}
