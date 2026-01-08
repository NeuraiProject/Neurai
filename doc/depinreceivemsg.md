# Implementation Guide for DePIN Clients (depinreceivemsg)

This documentation details the operation of the `depinreceivemsg` RPC command to facilitate the creation of client libraries (especially for AIs or web wallets).

## 1. Introduction to the Endpoint
The `depinreceivemsg` command allows a client to retrieve encrypted messages from the Neurai DePIN pool. Unlike `depingetmsg`, this endpoint is designed for environments where the server does not have access to the user's keys (non-custodial).

### RPC Call Parameters
1. **`token`** (string): The DePIN asset name (e.g., `NEURAI_POOL`). It must match the token configured on the node.
2. **`address`** (string): Client's Neurai address. It's used for access filtering and, optionally, for total response encryption.
3. **`timestamp`** (numeric, optional): Initial Unix time. The node will return messages with a timestamp greater than or equal to `(timestamp - 1)`.

---

## 2. Data Flow and Encryption
The system uses a double-layer protection scheme when the necessary security conditions are met.

### A. Privacy Layer (Optional)
If the server has an active pool key and the client has previously revealed their public key, the server will return an encrypted JSON object:

```json
{
  "encrypted": "hex_blob_ecies"
}
```

**Client Action:**
1. Deserialize the `hex_blob_ecies` (`CECIESEncryptedMessage` format).
2. Decrypt the content using the **Client's Private Key** and the **Pool's Public Key**.
3. The result will be the JSON array of messages described in section B.

### B. Standard Response (Message Array)
If the privacy layer is not active or has already been decrypted, an array of objects is received:

```json
[
  {
    "hash": "...",
    "token": "...",
    "sender": "...",
    "timestamp": 123456789,
    "message_type": "private|group",
    "encrypted_payload_hex": "...",
    "signature_hex": "..."
  }
]
```

---

## 3. Individual Message Decryption (`encrypted_payload_hex`)
The `encrypted_payload_hex` field contains the actual DePIN message, which is encrypted for multiple recipients (token holders).

### Payload Structure:
The payload follows a hybrid ECIES scheme:
1. **AES Key per Recipient:** A list of blocks where each block is an AES key encrypted with the public key of a specific recipient.
2. **Symmetrically Encrypted Data:** The actual message encrypted with the aforementioned AES key.

### Decryption Steps:
1. **Search:** The client must iterate through the recipient blocks looking for the one encrypted with its own public key.
2. **ECIES Decryption:** Use your own private key to obtain the 256-bit AES key.
3. **AES Decryption:** Use the AES key to decrypt the message body (usually plain text or internal JSON).

---

## 4. Security Validation
It is CRITICAL that the library performs these validations:
1. **Signature:** Validate `signature_hex` using the `sender` address and the message hash.
2. **Token:** Confirm that the `token` in the object matches the expected one.
3. **Origin:** If the privacy layer was used, validate that the server is who it claims to be using its pool key.

---

## 5. Cryptographic Requirements
- **Secp256k1:** For ECDSA signatures and ECDH key derivation.
- **ECIES:** Asymmetric encryption standard (based on Electrum/Bitcoin style).
- **AES-256-GCM/CBC:** For symmetric encryption of message data.
- **Base58Check:** For handling Neurai addresses.

---

## 6. Pagination for Memory-Limited Devices

For devices like ESP32 with limited memory, you can use pagination to receive messages in small batches.

### Additional Parameters:
4. **`after_hash`** (string, optional): Hash of the last received message. Empty `""` starts from the beginning.
5. **`limit`** (numeric, optional): Maximum number of messages to return per request. `0` or omitted = no limit.

### Paginated Response:
When using `limit > 0`, the response includes metadata:

```json
{
  "messages": [
    {
      "hash": "a1b2c3d4e5f6...",
      "token": "NEURAI_POOL",
      "sender": "NXn...",
      "timestamp": 1704067200,
      "message_type": "private",
      "encrypted_payload_hex": "...",
      "signature_hex": "..."
    },
    ...
  ],
  "has_more": true
}
```

### Pagination Flow:

1. **First request** (without previous messages):
   ```bash
   depinreceivemsg("NEURAI_POOL", "NXaddress", 0, "", 5)
   ```
   - `after_hash = ""` indicates starting from the beginning.
   - `limit = 5` requests a maximum of 5 messages.
   - Response: **The 5 oldest messages** (chronologically sorted) + `has_more: true`.

2. **Subsequent requests** (with cursor):
   ```bash
   depinreceivemsg("NEURAI_POOL", "NXaddress", 0, "last_msg_hash", 5)
   ```
   - `after_hash = "last_msg_hash"` continues after the last one received.
   - Response: next 5 messages + `has_more: true/false`.

3. **Completion**:
   - When `has_more: false`, no more messages are available.

### Usage Example (ESP32 in C++):

```cpp
#include <ArduinoJson.h>
#include <HTTPClient.h>

void syncDePINMessages() {
    String lastHash = "";
    bool hasMore = true;
    int messagesProcessed = 0;

    while (hasMore) {
        // Construct JSON-RPC request
        DynamicJsonDocument request(512);
        request["jsonrpc"] = "2.0";
        request["id"] = "1";
        request["method"] = "depinreceivemsg";
        request["params"][0] = "NEURAI_POOL";
        request["params"][1] = MY_NEURAI_ADDRESS;
        request["params"][2] = 0;           // timestamp (0 = all)
        request["params"][3] = lastHash;    // cursor
        request["params"][4] = 5;           // batch of 5 messages

        // Send HTTP request
        HTTPClient http;
        http.begin(NODE_URL);
        http.addHeader("Content-Type", "application/json");

        String payload;
        serializeJson(request, payload);
        int httpCode = http.POST(payload);

        // Process response
        if (httpCode == 200) {
            DynamicJsonDocument response(16384);
            DeserializationError error = deserializeJson(response, http.getString());

            if (!error) {
                JsonArray messages = response["result"]["messages"];

                for (JsonObject msg : messages) {
                    // Decrypt and process message
                    String hash = msg["hash"].as<String>();
                    String encryptedPayload = msg["encrypted_payload_hex"].as<String>();

                    // Here you implement your decryption logic
                    decryptAndStoreMessage(encryptedPayload);

                    lastHash = hash;  // Save for next iteration
                    messagesProcessed++;
                }

                // Check if there are more messages
                hasMore = response["result"]["has_more"] | false;

                Serial.printf("Processed %d messages. Has more: %s\n",
                             messagesProcessed, hasMore ? "true" : "false");
            } else {
                Serial.println("Error deserializing JSON");
                hasMore = false;
            }
        } else {
            Serial.printf("HTTP Error: %d\n", httpCode);
            hasMore = false;
        }

        http.end();
        delay(100);  // Small pause between requests
    }

    Serial.printf("Sync complete. Total messages: %d\n", messagesProcessed);
}
```

### Combined with Timestamp:

You can combine pagination with a timestamp filter to sync only new messages:

```bash
# First request: messages since January 1st, batch of 3
depinreceivemsg("NEURAI_POOL", "NXaddress", 1704067200, "", 3)
# Response: 3 oldest messages since that date

# Second request: next batch since that date
depinreceivemsg("NEURAI_POOL", "NXaddress", 1704067200, "last_hash", 3)
# Response: next 3 messages since that date
```

### Advantages of Pagination:

- **Reduced memory**: Process 5-10 messages at a time instead of 50+.
- **Gradual processing**: ECIES decryption distributed over multiple cycles.
- **Fail recovery**: If it fails mid-sync, you can continue from `lastHash`.
- **Backward compatible**: Standard clients can still use the traditional method without `limit`.

### Important Notes:

1. **Message Order**: Messages are returned in **chronological order** (oldest to newest). This facilitates sequential processing on devices with limited memory.

2. **Privacy layer**: If active, the entire response (including `has_more` metadata) comes encrypted in the `encrypted` field.

3. **Maximum Limit**: The server will reject `limit > 1000` to prevent abuse.

4. **Hash Not Found**: If you specify an `after_hash` that doesn't exist, you will receive an `after_hash not found in available messages` error.
