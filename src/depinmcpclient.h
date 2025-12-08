// Copyright (c) 2025 The Neurai Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_DEPINMCPCLIENT_H
#define NEURAI_DEPINMCPCLIENT_H

#include <string>
#include <vector>

/**
 * CDepinMCPClient - HTTP client for communicating with MCP (Model Context Protocol) servers
 *
 * This class handles HTTP POST requests to AI model servers like LM Studio, Ollama, etc.
 * It builds JSON payloads in OpenAI-compatible format and parses responses.
 */
class CDepinMCPClient
{
private:
    std::string baseUrl;        // Base URL (e.g., http://localhost:1234)
    std::string endpoint;       // API endpoint (e.g., /v1/chat/completions)
    std::string apiKey;         // Optional API key for authentication
    int timeout;                // Request timeout in seconds
    std::string modelName;      // Name of the loaded model

    /**
     * Make HTTP POST request to MCP server
     * @param url Full URL to send request to
     * @param body JSON body to send
     * @param response Output parameter for response body
     * @return true if request succeeded, false otherwise
     */
    bool MakeHTTPRequest(const std::string& url, const std::string& body, std::string& response);

public:
    /**
     * Constructor
     * @param url Base URL of MCP server
     * @param ep API endpoint path
     * @param key Optional API key
     * @param to Timeout in seconds
     */
    CDepinMCPClient(const std::string& url, const std::string& ep,
                    const std::string& key, int to);

    /**
     * Send a simple prompt to the MCP server
     * @param prompt User's prompt text
     * @param response Output parameter for AI response text
     * @return true if successful, false otherwise
     */
    bool SendPrompt(const std::string& prompt, std::string& response);

    /**
     * Send prompt with conversation context
     * @param prompt User's prompt text
     * @param context Previous messages for context
     * @param response Output parameter for AI response text
     * @return true if successful, false otherwise
     */
    bool SendWithContext(const std::string& prompt,
                        const std::vector<std::string>& context,
                        std::string& response);

    /**
     * Build JSON payload for MCP request (OpenAI-compatible format)
     * @param prompt User's prompt text
     * @param context Previous messages for context
     * @return JSON string ready to send
     */
    std::string BuildPayload(const std::string& prompt,
                            const std::vector<std::string>& context);

    /**
     * Parse JSON response from MCP server
     * @param jsonResponse Raw JSON response
     * @param text Output parameter for extracted text
     * @return true if parsing succeeded, false otherwise
     */
    bool ParseResponse(const std::string& jsonResponse, std::string& text);

    /**
     * Test connection to MCP server
     * @return true if server is reachable, false otherwise
     */
    bool TestConnection();

    /**
     * Fetch and store the model name from MCP server
     * @return true if model name was fetched successfully
     */
    bool FetchModelName();

    /**
     * Get the name of the currently loaded model
     * @return Model name or "unknown" if not available
     */
    std::string GetModelName() const { return modelName.empty() ? "unknown" : modelName; }
};

#endif // NEURAI_DEPINMCPCLIENT_H
