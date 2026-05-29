// Copyright (c) 2025 The Neurai Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "depinmcpclient.h"
#include "util.h"
#include "utilstrencodings.h"

#include <univalue.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/keyvalq_struct.h>

#include <sstream>

CDepinMCPClient::CDepinMCPClient(const std::string& url, const std::string& ep,
                                 const std::string& key, int to,
                                 int maxTok, double temp)
    : baseUrl(url), endpoint(ep), apiKey(key), timeout(to),
      maxTokens(maxTok), temperature(temp), modelName("")
{
}

std::string CDepinMCPClient::GetModelName() const
{
    LOCK(cs_model);
    return modelName.empty() ? "unknown" : modelName;
}

std::string CDepinMCPClient::BuildPayload(const std::string& prompt,
                                          const std::vector<std::string>& context)
{
    UniValue payload(UniValue::VOBJ);

    // LM Studio / OpenAI-compatible format
    payload.push_back(Pair("model", "local-model"));

    // Build messages array
    UniValue messages(UniValue::VARR);

    // System message
    UniValue systemMsg(UniValue::VOBJ);
    systemMsg.push_back(Pair("role", "system"));
    systemMsg.push_back(Pair("content", "You are a helpful assistant for the Neurai community."));
    messages.push_back(systemMsg);

    // Add context messages if provided
    for (size_t i = 0; i < context.size(); i++) {
        UniValue contextMsg(UniValue::VOBJ);
        contextMsg.push_back(Pair("role", i % 2 == 0 ? "user" : "assistant"));
        contextMsg.push_back(Pair("content", context[i]));
        messages.push_back(contextMsg);
    }

    // Add current prompt
    UniValue userMsg(UniValue::VOBJ);
    userMsg.push_back(Pair("role", "user"));
    userMsg.push_back(Pair("content", prompt));
    messages.push_back(userMsg);

    payload.push_back(Pair("messages", messages));
    payload.push_back(Pair("temperature", temperature));
    payload.push_back(Pair("max_tokens", maxTokens));
    // NOTE: streaming intentionally disabled. The DePIN chat delivers discrete pooled
    // messages, not a live channel, so token-by-token streaming adds no value; long
    // answers are handled by response fragmentation in the worker instead.
    payload.push_back(Pair("stream", false));

    return payload.write();
}

bool CDepinMCPClient::ParseResponse(const std::string& jsonResponse, std::string& text)
{
    try {
        UniValue response;
        if (!response.read(jsonResponse)) {
            LogPrintf("MCPClient: Failed to parse JSON response\n");
            return false;
        }

        // Extract model name if present
        const UniValue& model = find_value(response, "model");
        if (model.isStr()) {
            LOCK(cs_model);
            modelName = model.get_str();
            LogPrintf("MCPClient: Model name from response: %s\n", modelName);
        }

        // OpenAI format: response.choices[0].message.content
        const UniValue& choices = find_value(response, "choices");
        if (!choices.isArray() || choices.size() == 0) {
            LogPrintf("MCPClient: No choices in response\n");
            return false;
        }

        const UniValue& firstChoice = choices[0];
        const UniValue& message = find_value(firstChoice, "message");
        if (!message.isObject()) {
            LogPrintf("MCPClient: No message in choice\n");
            return false;
        }

        const UniValue& content = find_value(message, "content");
        if (!content.isStr()) {
            LogPrintf("MCPClient: No content in message\n");
            return false;
        }

        text = content.get_str();
        return true;

    } catch (const std::exception& e) {
        LogPrintf("MCPClient: Exception parsing response: %s\n", e.what());
        return false;
    }
}

bool CDepinMCPClient::MakeHTTPRequest(const std::string& url, const std::string& body, std::string& response)
{
    struct event_base* base = event_base_new();
    if (!base) {
        LogPrintf("MCPClient: Failed to create event base\n");
        return false;
    }

    // Parse URL
    struct evhttp_uri* uri = evhttp_uri_parse(url.c_str());
    if (!uri) {
        LogPrintf("MCPClient: Invalid URL: %s\n", url);
        event_base_free(base);
        return false;
    }

    const char* host = evhttp_uri_get_host(uri);
    int port = evhttp_uri_get_port(uri);
    if (port == -1) port = 80;
    const char* path = evhttp_uri_get_path(uri);
    if (!path || strlen(path) == 0) path = "/";

    // Create connection
    struct evhttp_connection* conn = evhttp_connection_base_new(base, NULL, host, port);
    if (!conn) {
        LogPrintf("MCPClient: Failed to create connection to %s:%d\n", host, port);
        evhttp_uri_free(uri);
        event_base_free(base);
        return false;
    }

    evhttp_connection_set_timeout(conn, timeout);

    // Create request
    struct evhttp_request* req = evhttp_request_new([](struct evhttp_request* req, void* ctx) {
        std::string* responsePtr = static_cast<std::string*>(ctx);

        if (!req) {
            LogPrintf("MCPClient: Request failed (null request in callback)\n");
            return;
        }

        int code = evhttp_request_get_response_code(req);
        LogPrintf("MCPClient: HTTP response code: %d\n", code);

        struct evbuffer* buf = evhttp_request_get_input_buffer(req);
        size_t len = evbuffer_get_length(buf);
        LogPrintf("MCPClient: Response buffer length: %d\n", (int)len);

        if (len > 0) {
            char* data = new char[len + 1];
            evbuffer_copyout(buf, data, len);
            data[len] = '\0';
            *responsePtr = std::string(data, len);
            delete[] data;
            LogPrintf("MCPClient: Captured response data\n");
        }

        if (code != 200) {
            LogPrintf("MCPClient: HTTP error %d, body: %s\n", code, responsePtr->substr(0, 200));
        }
    }, &response);

    if (!req) {
        LogPrintf("MCPClient: Failed to create request\n");
        evhttp_connection_free(conn);
        evhttp_uri_free(uri);
        event_base_free(base);
        return false;
    }

    // Set headers
    struct evkeyvalq* headers = evhttp_request_get_output_headers(req);
    evhttp_add_header(headers, "Content-Type", "application/json");
    evhttp_add_header(headers, "Host", host);

    if (!apiKey.empty()) {
        std::string authHeader = "Bearer " + apiKey;
        evhttp_add_header(headers, "Authorization", authHeader.c_str());
    }

    // Add body
    struct evbuffer* output = evhttp_request_get_output_buffer(req);
    evbuffer_add(output, body.c_str(), body.length());

    // Make request
    std::string fullPath = path;
    int result = evhttp_make_request(conn, req, EVHTTP_REQ_POST, fullPath.c_str());

    if (result != 0) {
        LogPrintf("MCPClient: Failed to make request\n");
        evhttp_uri_free(uri);
        event_base_free(base);
        return false;
    }

    // Run event loop
    event_base_dispatch(base);

    // Cleanup
    evhttp_connection_free(conn);
    evhttp_uri_free(uri);
    event_base_free(base);

    LogPrintf("MCPClient: MakeHTTPRequest finished, response length: %d\n", (int)response.length());
    return !response.empty();
}

bool CDepinMCPClient::SendPrompt(const std::string& prompt, std::string& response)
{
    std::vector<std::string> emptyContext;
    return SendWithContext(prompt, emptyContext, response);
}

bool CDepinMCPClient::SendWithContext(const std::string& prompt,
                                      const std::vector<std::string>& context,
                                      std::string& response)
{
    // Build payload
    std::string payload = BuildPayload(prompt, context);

    LogPrintf("MCPClient: Sending request to %s%s\n", baseUrl, endpoint);
    LogPrintf("MCPClient: Payload: %s\n", payload);

    // Make HTTP request
    std::string fullUrl = baseUrl + endpoint;
    std::string rawResponse;

    if (!MakeHTTPRequest(fullUrl, payload, rawResponse)) {
        LogPrintf("MCPClient: HTTP request failed\n");
        return false;
    }

    LogPrintf("MCPClient: Raw response (%d bytes): %s\n", rawResponse.length(), rawResponse.substr(0, 500));

    // Parse response
    if (!ParseResponse(rawResponse, response)) {
        LogPrintf("MCPClient: Failed to parse response\n");
        return false;
    }

    LogPrintf("MCPClient: Successfully received response (%d bytes)\n", response.length());
    return true;
}

bool CDepinMCPClient::TestConnection()
{
    LogPrintf("MCPClient: Testing connection to %s%s\n", baseUrl, endpoint);

    std::string testPrompt = "test";
    std::string response;

    // Try to send a simple test prompt
    bool success = SendPrompt(testPrompt, response);

    if (success) {
        LogPrintf("MCPClient: Connection test successful\n");
    } else {
        LogPrintf("MCPClient: Connection test failed\n");
    }

    return success;
}

bool CDepinMCPClient::FetchModelName()
{
    LogPrintf("MCPClient: Fetching model name from %s/v1/models\n", baseUrl);

    // Try to get model list from /v1/models endpoint (OpenAI-compatible)
    std::string modelsUrl = baseUrl + "/v1/models";
    std::string response;

    // Create a simple GET request - we'll use a minimal payload
    struct event_base* base = event_base_new();
    if (!base) {
        LogPrintf("MCPClient: Failed to create event base for model fetch\n");
        return false;
    }

    struct evhttp_uri* uri = evhttp_uri_parse(modelsUrl.c_str());
    if (!uri) {
        LogPrintf("MCPClient: Invalid URL: %s\n", modelsUrl);
        event_base_free(base);
        return false;
    }

    const char* host = evhttp_uri_get_host(uri);
    int port = evhttp_uri_get_port(uri);
    if (port == -1) port = 80;

    struct evhttp_connection* conn = evhttp_connection_base_new(base, NULL, host, port);
    if (!conn) {
        LogPrintf("MCPClient: Failed to create connection for model fetch\n");
        evhttp_uri_free(uri);
        event_base_free(base);
        return false;
    }

    evhttp_connection_set_timeout(conn, 10); // Short timeout for model query

    struct evhttp_request* req = evhttp_request_new([](struct evhttp_request* req, void* ctx) {
        std::string* responsePtr = static_cast<std::string*>(ctx);
        if (!req) return;

        struct evbuffer* buf = evhttp_request_get_input_buffer(req);
        size_t len = evbuffer_get_length(buf);
        if (len > 0) {
            char* data = new char[len + 1];
            evbuffer_copyout(buf, data, len);
            data[len] = '\0';
            *responsePtr = std::string(data, len);
            delete[] data;
        }
    }, &response);

    if (!req) {
        evhttp_connection_free(conn);
        evhttp_uri_free(uri);
        event_base_free(base);
        return false;
    }

    struct evkeyvalq* headers = evhttp_request_get_output_headers(req);
    evhttp_add_header(headers, "Host", host);
    if (!apiKey.empty()) {
        std::string authHeader = "Bearer " + apiKey;
        evhttp_add_header(headers, "Authorization", authHeader.c_str());
    }

    int result = evhttp_make_request(conn, req, EVHTTP_REQ_GET, "/v1/models");
    if (result != 0) {
        evhttp_uri_free(uri);
        event_base_free(base);
        return false;
    }

    event_base_dispatch(base);
    evhttp_connection_free(conn);
    evhttp_uri_free(uri);
    event_base_free(base);

    if (response.empty()) {
        LogPrintf("MCPClient: Empty response from /v1/models\n");
        return false;
    }

    // Parse response to get model name
    try {
        UniValue models;
        if (!models.read(response)) {
            LogPrintf("MCPClient: Failed to parse models JSON\n");
            return false;
        }

        // LM Studio format: {"data": [{"id": "model-name", ...}]}
        const UniValue& data = find_value(models, "data");
        if (data.isArray() && data.size() > 0) {
            const UniValue& firstModel = data[0];
            const UniValue& id = find_value(firstModel, "id");
            if (id.isStr()) {
                {
                    LOCK(cs_model);
                    modelName = id.get_str();
                }
                LogPrintf("MCPClient: Loaded model: %s\n", id.get_str());
                return true;
            }
        }

        LogPrintf("MCPClient: Could not extract model name from response\n");
        return false;

    } catch (const std::exception& e) {
        LogPrintf("MCPClient: Exception parsing models: %s\n", e.what());
        return false;
    }
}
