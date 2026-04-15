package utils;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedClientHelloExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;

/**
 * Utility class for converting TLS protocol messages to JSON format.
 * Extracts and serializes messages from a TLS workflow trace into structured JSON files.
 * Each message type (ClientHello, ServerHello, Certificate, etc.) is serialized to its own JSON file.
 * 
 * @author TLS Analyzer Team
 */
public class MessageToJson {
	
    private WorkflowTrace trace;  // The workflow trace containing TLS actions and messages

    private static final Logger LOGGER = LogManager.getLogger(MessageToJson.class);

    private static final String DEFAULT_OUTPUT_DIR = "src/main/resources/messages/";  // Default output directory for JSON files

    /**
     * Constructor - initializes the converter with a workflow trace
     * 
     * @param trace The TLS workflow trace to extract messages from
     */
    public MessageToJson(WorkflowTrace trace) {
        this.trace = trace;
    }

    /**
     * Extracts all messages from the workflow trace and converts them to JSON format.
     * Iterates through all TLS actions (send/receive) and processes each message.
     * 
     * @param TSL_Version The TLS version being analyzed (used for output directory structure)
     */
    public void informationsExtraction(String TSL_Version) {
        List<TlsAction> actions = trace.getTlsActions();  // Get all actions from the trace
        for (int i = 0; i < actions.size(); i++) {
            TlsAction action = actions.get(i);
            List<ProtocolMessage> messages = resolveMessages(action);  // Extract messages from the action
            
            if (messages != null && !messages.isEmpty()) {
                for (ProtocolMessage msg : messages) {
                    toJson(msg, null, TSL_Version);  // Convert each message to JSON
                }
            }
        }
    }

    /**
     * Resolves and extracts messages from a TLS action.
     * Handles both SendAction and ReceiveAction types appropriately.
     * 
     * @param action The TLS action to extract messages from
     * @return List of protocol messages from the action, or empty list if none found
     */
    private List<ProtocolMessage> resolveMessages(TlsAction action) {
        // For SendAction: get sent messages or configured messages
        if (action instanceof SendAction) {
            List<ProtocolMessage> sent = ((SendAction) action).getSentMessages();
            if (sent != null && !sent.isEmpty()) return sent;
            return ((SendAction) action).getConfiguredMessages();
        }
        
        // For ReceiveAction: get received messages or expected messages
        if (action instanceof ReceiveAction) {
            List<ProtocolMessage> received = ((ReceiveAction) action).getReceivedMessages();
            if (received != null && !received.isEmpty()) return received;
            return ((ReceiveAction) action).getExpectedMessages();
        }
        
        return Collections.emptyList();  // Return empty list for unknown action types
    }

    /**
     * Converts a single protocol message to JSON and saves it to a file.
     * 
     * @param message The protocol message to convert
     * @param outputPath Custom output path (can be null to use default path)
     * @param TLS_Version TLS version for directory structure
     */
    public void toJson(ProtocolMessage message, String outputPath, String TLS_Version) {
        String resolvedPath = (outputPath != null)
            ? outputPath
            : resolveOutputPath(message, TLS_Version);  // Use custom or default path
        ensureFileExists(resolvedPath, message);  // Create directory and file if needed
        writeToFile(buildJson(message), resolvedPath);  // Write JSON to file
    }

    /**
     * Determines the output file path based on message type and TLS version.
     * Format: DEFAULT_OUTPUT_DIR/{TLS_Version}/{MessageType}.json
     * 
     * @param message The protocol message
     * @param TLS_Version The TLS version
     * @return Resolved output file path
     */
    private String resolveOutputPath(ProtocolMessage message, String TLS_Version) {
        String messageType = message.getClass().getSimpleName();  // e.g., "ClientHelloMessage"
        return DEFAULT_OUTPUT_DIR + TLS_Version + "/" + messageType + ".json";
    }

    /**
     * Ensures that the output directory and file exist before writing.
     * Creates directories recursively if they don't exist.
     * Logs a warning if the file already exists (will be overwritten).
     * 
     * @param outputPath The output file path
     * @param message The message being written (for logging)
     */
    private void ensureFileExists(String outputPath, ProtocolMessage message) {
        File file = new File(outputPath);
        File parentDir = file.getParentFile();

        // Create parent directories if they don't exist
        if (parentDir != null && !parentDir.exists()) {
            if (parentDir.mkdirs()) {
                LOGGER.info("Created directory: {}", parentDir.getAbsolutePath());
            } else {
                LOGGER.error("Failed to create directory: {}", parentDir.getAbsolutePath());
                return;
            }
        }

        // Create the file if it doesn't exist
        if (!file.exists()) {
            try {
                if (file.createNewFile()) {
                    LOGGER.info("Created file for {}: {}",
                        message.getClass().getSimpleName(), file.getAbsolutePath());
                }
            } catch (IOException e) {
                LOGGER.error("Failed to create file: {}", outputPath, e);
            }
        } else {
            LOGGER.warn("File already exists and will be overwritten: {}", outputPath);
        }
    }

    /**
     * Writes a JSON object to a file with pretty formatting.
     * 
     * @param json The JSON object to write
     * @param outputPath The output file path
     */
    private void writeToFile(JsonObject json, String outputPath) {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();  // Create pretty-printer
        try (FileWriter writer = new FileWriter(outputPath)) {
            gson.toJson(json, writer);  // Write JSON to file
            LOGGER.info("Message written to: {}", outputPath);
        } catch (IOException e) {
            LOGGER.error("Error writing JSON file: {}", outputPath, e);
        }
    }

    /**
     * Builds a JSON object from a protocol message.
     * Routes to message-type-specific serializers based on the message class.
     * 
     * @param message The protocol message to serialize
     * @return JsonObject containing the serialized message
     */
    private JsonObject buildJson(ProtocolMessage message) {
        JsonObject json = new JsonObject();
        json.addProperty("messageClass", message.getClass().getSimpleName());  // Add message type
        json.addProperty("timestamp", LocalDateTime.now().toString());  // Add timestamp

        // Route to appropriate serializer based on message type
        if (message instanceof ClientHelloMessage) {
            serializeClientHello((ClientHelloMessage) message, json);
        } else if (message instanceof ServerHelloMessage) {
            serializeServerHello((ServerHelloMessage) message, json);
        } else if (message instanceof CertificateMessage) {
            serializeCertificate((CertificateMessage) message, json);
        } else if (message instanceof CertificateVerifyMessage) {
            serializeCertificateVerify((CertificateVerifyMessage) message, json);
        } else if (message instanceof FinishedMessage) {
            serializeFinished((FinishedMessage) message, json);
        } else if (message instanceof AlertMessage) {
            serializeAlert((AlertMessage) message, json);
        } else if (message instanceof ApplicationMessage) {
            serializeApplication((ApplicationMessage) message, json);
        } else {
            // Log warning for unhandled message types
            LOGGER.warn("Unhandled message type: {}", message.getClass().getSimpleName());
            json.addProperty("warning", "Message type not explicitly handled");
        }

        return json;
    }

    // ==================== MESSAGE TYPE SERIALIZERS ====================

    /**
     * Serializes a ClientHello message to JSON.
     * Includes legacy version, random, session ID, cipher suites, compression methods, and ECH status.
     * 
     * @param m The ClientHello message
     * @param json The JSON object to populate
     */
    private void serializeClientHello(ClientHelloMessage m, JsonObject json) {
        addHandshakeHeader(m, json);  // Add handshake type and length

        // Protocol version (legacy_version field)
        if (m.getProtocolVersion() != null && m.getProtocolVersion().getValue() != null) {
            json.addProperty("legacyVersion",
                decodeProtocolVersion(m.getProtocolVersion().getValue()));
        }
        
        // Client random (32 bytes)
        if (m.getRandom() != null && m.getRandom().getValue() != null) {
            json.addProperty("clientRandom", toCleanHex(m.getRandom().getValue()));
        }
        
        // Session ID (used for session resumption)
        if (m.getSessionIdLength() != null && m.getSessionIdLength().getValue() != null) {
            json.addProperty("legacySessionIdLength", m.getSessionIdLength().getValue());
        }
        if (m.getSessionId() != null && m.getSessionId().getValue() != null
                && m.getSessionId().getValue().length > 0) {
            json.addProperty("legacySessionId", toCleanHex(m.getSessionId().getValue()));
        }
        
        // Cipher suites list
        if (m.getCipherSuiteLength() != null && m.getCipherSuiteLength().getValue() != null) {
            json.addProperty("cipherSuiteLength", m.getCipherSuiteLength().getValue());
        }
        if (m.getCipherSuites() != null && m.getCipherSuites().getValue() != null) {
            json.add("cipherSuites", decodeCipherSuiteList(m.getCipherSuites().getValue()));
        }
        
        // Compression methods (legacy - always "none" in modern TLS)
        if (m.getCompressionLength() != null && m.getCompressionLength().getValue() != null) {
            json.addProperty("legacyCompressionMethodsLength", m.getCompressionLength().getValue());
        }
        if (m.getCompressions() != null && m.getCompressions().getValue() != null) {
            json.addProperty("legacyCompressionMethods",
                m.getCompressions().getValue()[0] == 0 ? "none (0x00)" : toCleanHex(m.getCompressions().getValue()));
        }

        // Check for Encrypted Client Hello (ECH) extension
        boolean hasEch = m.getExtensions() != null && m.getExtensions().stream()
            .anyMatch(e -> e instanceof EncryptedClientHelloExtensionMessage);
        json.addProperty("encryptedClientHello", hasEch);

        serializeExtensions(m, json);  // Serialize all extensions
    }

    /**
     * Serializes a ServerHello message to JSON.
     * Includes selected version, random, session ID, cipher suite, and compression method.
     * 
     * @param m The ServerHello message
     * @param json The JSON object to populate
     */
    private void serializeServerHello(ServerHelloMessage m, JsonObject json) {
        addHandshakeHeader(m, json);
        
        // Selected protocol version
        if (m.getProtocolVersion() != null && m.getProtocolVersion().getValue() != null) {
            json.addProperty("selectedVersion",
                decodeProtocolVersion(m.getProtocolVersion().getValue()));
        }
        
        // Server random (32 bytes)
        if (m.getRandom() != null && m.getRandom().getValue() != null) {
            json.addProperty("Random", toCleanHex(m.getRandom().getValue()));
        }
        
        // Session ID (echo of client's session ID or new value)
        if (m.getSessionIdLength() != null && m.getSessionIdLength().getValue() != null) {
            json.addProperty("legacySessionIdLength", m.getSessionIdLength().getValue());
        }
        if (m.getSessionId() != null && m.getSessionId().getValue() != null
                && m.getSessionId().getValue().length > 0) {
            json.addProperty("legacySessionId", toCleanHex(m.getSessionId().getValue()));
        }
        
        // Selected cipher suite
        if (m.getSelectedCipherSuite() != null && m.getSelectedCipherSuite().getValue() != null) {
            json.addProperty("selectedCipherSuite",
                decodeCipherSuite(m.getSelectedCipherSuite().getValue()));
        }
        
        // Selected compression method (always 0x00 in modern TLS)
        if (m.getSelectedCompressionMethod() != null
                && m.getSelectedCompressionMethod().getValue() != null) {
            json.addProperty("selectedCompressionMethod",
                m.getSelectedCompressionMethod().getValue() == 0
                    ? "0x00"
                    : String.format("0x%02X", m.getSelectedCompressionMethod().getValue()));
        }

        serializeExtensions(m, json);
    }

    /**
     * Serializes a Certificate message to JSON.
     * Contains the certificate chain length and raw certificate data.
     * 
     * @param m The Certificate message
     * @param json The JSON object to populate
     */
    private void serializeCertificate(CertificateMessage m, JsonObject json) {
        addHandshakeHeader(m, json);

        // Total length of the certificates list
        if (m.getCertificatesListLength() != null && m.getCertificatesListLength().getValue() != null) {
            json.addProperty("certificatesListLength", m.getCertificatesListLength().getValue());
        }
        
        // Raw certificate chain bytes (each certificate includes its length prefix)
        if (m.getCertificatesListBytes() != null && m.getCertificatesListBytes().getValue() != null) {
            json.addProperty("certificatesListBytes",
                toCleanHex(m.getCertificatesListBytes().getValue()));
        }
    }

    /**
     * Serializes a CertificateVerify message to JSON.
     * Contains the signature algorithm and the signature itself.
     * 
     * @param m The CertificateVerify message
     * @param json The JSON object to populate
     */
    private void serializeCertificateVerify(CertificateVerifyMessage m, JsonObject json) {
        addHandshakeHeader(m, json);

        // Signature algorithm (e.g., rsa_pkcs1_sha256)
        if (m.getSignatureHashAlgorithm() != null && m.getSignatureHashAlgorithm().getValue() != null) {
            json.addProperty("signatureHashAlgorithm",
                decodeSignatureAlgorithm(m.getSignatureHashAlgorithm().getValue()));
        }
        
        // Signature length
        if (m.getSignatureLength() != null && m.getSignatureLength().getValue() != null) {
            json.addProperty("signatureLength", m.getSignatureLength().getValue());
        }
        
        // The actual signature data
        if (m.getSignature() != null && m.getSignature().getValue() != null) {
            json.addProperty("signature", toCleanHex(m.getSignature().getValue()));
        }
    }

    /**
     * Serializes a Finished message to JSON.
     * Contains the verify data which is a PRF hash of all previous handshake messages.
     * 
     * @param m The Finished message
     * @param json The JSON object to populate
     */
    private void serializeFinished(FinishedMessage m, JsonObject json) {
        addHandshakeHeader(m, json);

        // Verify data (hash of all handshake messages so far)
        if (m.getVerifyData() != null && m.getVerifyData().getValue() != null) {
            json.addProperty("verifyData", toCleanHex(m.getVerifyData().getValue()));
        }
    }

    /**
     * Serializes an Alert message to JSON.
     * Contains the alert level (warning/fatal) and description.
     * 
     * @param m The Alert message
     * @param json The JSON object to populate
     */
    private void serializeAlert(AlertMessage m, JsonObject json) {
        // Alert level (1=warning, 2=fatal)
        if (m.getLevel() != null && m.getLevel().getValue() != null) {
            json.addProperty("alertLevel", decodeAlertLevel(m.getLevel().getValue()));
        }
        
        // Alert description (e.g., close_notify, handshake_failure)
        if (m.getDescription() != null && m.getDescription().getValue() != null) {
            json.addProperty("alertDescription", decodeAlertDescription(m.getDescription().getValue()));
        }
    }

    /**
     * Serializes an Application message (application data) to JSON.
     * Contains the encrypted or plaintext application data.
     * 
     * @param m The Application message
     * @param json The JSON object to populate
     */
    private void serializeApplication(ApplicationMessage m, JsonObject json) {
        // Application data bytes (may be encrypted)
        if (m.getData() != null && m.getData().getValue() != null) {
            json.addProperty("applicationData", toCleanHex(m.getData().getValue()));
        }
    }

    // ==================== HELPER METHODS ====================

    /**
     * Adds common handshake header fields to the JSON object.
     * Includes handshake type and message length.
     * 
     * @param m The handshake message
     * @param json The JSON object to populate
     */
    private void addHandshakeHeader(HandshakeMessage m, JsonObject json) {
        // Handshake message type (ClientHello, ServerHello, etc.)
        if (m.getType() != null && m.getType().getValue() != null) {
            json.addProperty("handshakeType",
                decodeHandshakeType(m.getType().getValue()));
        }
        
        // Length of the handshake message (excluding the header)
        if (m.getLength() != null && m.getLength().getValue() != null) {
            json.addProperty("handshakeLength", m.getLength().getValue());
        }
    }

    /**
     * Serializes all extensions present in a handshake message.
     * Processes each extension and adds its name, length, and decoded content.
     * 
     * @param m The handshake message containing extensions
     * @param json The JSON object to populate
     */
    private void serializeExtensions(HandshakeMessage m, JsonObject json) {
        // Total length of all extensions combined
        if (m.getExtensionBytes() != null && m.getExtensionBytes().getValue() != null) {
            json.addProperty("extensionsTotalLength", m.getExtensionBytes().getValue().length);
        }
        
        // Process each extension individually
        if (m.getExtensions() != null && !m.getExtensions().isEmpty()) {
            JsonArray extensionsArray = new JsonArray();
            
            for (ExtensionMessage ext : m.getExtensions()) {
                JsonObject extJson = new JsonObject();

                // Extension type (e.g., key_share, supported_versions)
                byte[] typeBytes = ext.getExtensionType() != null
                    ? ext.getExtensionType().getValue() : null;
                extJson.addProperty("extensionName", decodeExtensionType(typeBytes));

                // Extension data length
                if (ext.getExtensionLength() != null && ext.getExtensionLength().getValue() != null) {
                    extJson.addProperty("extensionLength", ext.getExtensionLength().getValue());
                }
                
                // Extension content (decoded based on type)
                if (ext.getExtensionContent() != null && ext.getExtensionContent().getValue() != null) {
                    extJson.addProperty("extensionContent",
                        decodeExtensionContent(typeBytes, ext.getExtensionContent().getValue()));
                }

                extensionsArray.add(extJson);
            }
            json.add("extensions", extensionsArray);
        } else {
            json.addProperty("extensions", "NO EXTENSIONS");
        }
    }

    // ==================== DECODING METHODS ====================

    /**
     * Decodes protocol version bytes to a readable string.
     * 
     * @param bytes The 2-byte protocol version
     * @return Readable version string (e.g., "TLS 1.2 (0x0303)")
     */
    private String decodeProtocolVersion(byte[] bytes) {
        if (bytes == null || bytes.length < 2) return "unknown";
        for (ProtocolVersion v : ProtocolVersion.values()) {
            if (Arrays.equals(v.getValue(), bytes)) {
                return v.name().replace("_", " ")
                    + String.format(" (0x%02X%02X)", bytes[0] & 0xFF, bytes[1] & 0xFF);
            }
        }
        return String.format("Unknown (0x%02X%02X)", bytes[0] & 0xFF, bytes[1] & 0xFF);
    }

    /**
     * Decodes cipher suite bytes to a readable string.
     * 
     * @param bytes The 2-byte cipher suite identifier
     * @return Cipher suite name or hex representation if unknown
     */
    private String decodeCipherSuite(byte[] bytes) {
        if (bytes == null || bytes.length < 2) return "unknown";
        for (CipherSuite cs : CipherSuite.values()) {
            if (Arrays.equals(cs.getByteValue(), bytes)) {
                return cs.name();
            }
        }
        return String.format("Unknown (0x%02X%02X)", bytes[0] & 0xFF, bytes[1] & 0xFF);
    }

    /**
     * Decodes a list of cipher suites (consecutive 2-byte pairs) to a JSON array.
     * 
     * @param bytes The raw cipher suite bytes
     * @return JsonArray of decoded cipher suite names
     */
    private JsonArray decodeCipherSuiteList(byte[] bytes) {
        JsonArray array = new JsonArray();
        if (bytes == null) return array;
        for (int i = 0; i + 1 < bytes.length; i += 2) {
            array.add(decodeCipherSuite(new byte[]{bytes[i], bytes[i + 1]}));
        }
        return array;
    }

    /**
     * Decodes extension type bytes to a readable string.
     * 
     * @param bytes The 2-byte extension type
     * @return Extension name or "GREASE_xx" for GREASE values, hex for unknown
     */
    private String decodeExtensionType(byte[] bytes) {
        if (bytes == null || bytes.length < 2) return "unknown";
        
        // Check for GREASE values (used for extensibility testing)
        int value = ((bytes[0] & 0xFF) << 8) | (bytes[1] & 0xFF);
        if (isGreaseValue(value)) {
            return String.format("GREASE_%02X%02X (test value)", bytes[0] & 0xFF, bytes[1] & 0xFF);
        }
        
        // Look up known extension types
        for (ExtensionType type : ExtensionType.values()) {
            if (Arrays.equals(type.getValue(), bytes)) {
                return type.name().toLowerCase();
            }
        }
        return String.format("Unknown (0x%02X%02X)", bytes[0] & 0xFF, bytes[1] & 0xFF);
    }
    
    /**
     * Checks if a value is a GREASE (Generate Random Extensions And Sustain Extensibility) value.
     * GREASE values are used to test that implementations handle unknown values correctly.
     * 
     * @param value The 2-byte integer to check
     * @return true if the value is a GREASE value
     */
    private boolean isGreaseValue(int value) {
        // GREASE values follow the pattern: 0x1A1A, 0x2A2A, 0x3A3A, ..., 0xFAFA
        return (value & 0x0F0F) == 0x0A0A && (value & 0xF0F0) != 0;
    }

    /**
     * Decodes extension content based on the extension type.
     * Specific decoders for supported_versions, key_share, and signature_algorithms.
     * 
     * @param typeBytes The extension type bytes
     * @param contentBytes The raw extension content
     * @return Decoded content as a readable string
     */
    private String decodeExtensionContent(byte[] typeBytes, byte[] contentBytes) {
        if (contentBytes == null) return "";
        if (typeBytes == null) return toCleanHex(contentBytes);

        for (ExtensionType type : ExtensionType.values()) {
            if (!Arrays.equals(type.getValue(), typeBytes)) continue;
            switch (type) {
                case SUPPORTED_VERSIONS:
                    return decodeVersionList(contentBytes);  // Protocol versions list
                case KEY_SHARE:
                    return decodeKeyShare(contentBytes);     // Key share entries
                case SIGNATURE_AND_HASH_ALGORITHMS:
                    return decodeSignatureAlgorithmList(contentBytes);  // Signature algorithms
                default:
                    return toCleanHex(contentBytes);  // Unknown extension - return raw hex
            }
        }
        return toCleanHex(contentBytes);
    }

    /**
     * Decodes a protocol version list (used in supported_versions extension).
     * 
     * @param bytes The version list bytes
     * @return Comma-separated list of protocol versions
     */
    private String decodeVersionList(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return "";
        // ServerHello: 2 bytes = single version
        if (bytes.length == 2) return decodeProtocolVersion(bytes);
        // ClientHello: 1 byte length prefix + list
        StringBuilder sb = new StringBuilder();
        int start = (bytes.length % 2 == 1) ? 1 : 0;  // Skip length byte if present
        for (int i = start; i + 1 < bytes.length; i += 2) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(decodeProtocolVersion(new byte[]{bytes[i], bytes[i + 1]}));
        }
        return sb.toString();
    }

    /**
     * Decodes a KeyShare extension entry.
     * Format: named group (2 bytes) + key length (2 bytes) + public key
     * 
     * @param bytes The KeyShare extension bytes
     * @return Decoded KeyShare information
     */
    private String decodeKeyShare(byte[] bytes) {
        if (bytes == null || bytes.length < 4) return toCleanHex(bytes);
        int groupId = ((bytes[0] & 0xFF) << 8) | (bytes[1] & 0xFF);  // Named group
        int keyLen  = ((bytes[2] & 0xFF) << 8) | (bytes[3] & 0xFF);  // Key length
        byte[] key  = Arrays.copyOfRange(bytes, 4, Math.min(4 + keyLen, bytes.length));  // Public key
        return String.format("namedGroup=%s, keyLength=%d, publicKey=%s",
            decodeNamedGroup(groupId), keyLen, toCleanHex(key));
    }

    /**
     * Decodes a signature algorithm list (used in signature_algorithms extension).
     * 
     * @param bytes The signature algorithm list bytes
     * @return Comma-separated list of signature algorithms
     */
    private String decodeSignatureAlgorithmList(byte[] bytes) {
        if (bytes == null || bytes.length < 2) return toCleanHex(bytes);
        StringBuilder sb = new StringBuilder();
        // First 2 bytes are the total length of the list - skip them
        for (int i = 2; i + 1 < bytes.length; i += 2) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(decodeSignatureAlgorithm(new byte[]{bytes[i], bytes[i + 1]}));
        }
        return sb.toString();
    }

    /**
     * Decodes a signature algorithm from 2-byte identifier.
     * Supports common TLS 1.2 and 1.3 signature algorithms.
     * 
     * @param bytes The 2-byte signature algorithm identifier
     * @return Readable signature algorithm name
     */
    private String decodeSignatureAlgorithm(byte[] bytes) {
        if (bytes == null || bytes.length < 2) return "unknown";
        int id = ((bytes[0] & 0xFF) << 8) | (bytes[1] & 0xFF);
        switch (id) {
            // RSA PKCS#1 with SHA-2
            case 0x0401: return "rsa_pkcs1_sha256";
            case 0x0501: return "rsa_pkcs1_sha384";
            case 0x0601: return "rsa_pkcs1_sha512";
            // ECDSA with SHA-2
            case 0x0403: return "ecdsa_secp256r1_sha256";
            case 0x0503: return "ecdsa_secp384r1_sha384";
            case 0x0603: return "ecdsa_secp521r1_sha512";
            // RSA-PSS (TLS 1.3)
            case 0x0804: return "rsa_pss_rsae_sha256";
            case 0x0805: return "rsa_pss_rsae_sha384";
            case 0x0806: return "rsa_pss_rsae_sha512";
            // Legacy algorithms
            case 0x0201: return "rsa_pkcs1_sha1";
            case 0x0203: return "ecdsa_sha1";
            default:     return String.format("Unknown (0x%04X)", id);
        }
    }

    /**
     * Decodes a named group (elliptic curve or finite field) from its ID.
     * 
     * @param id The named group identifier
     * @return Readable group name
     */
    private String decodeNamedGroup(int id) {
        switch (id) {
            // NIST curves (RFC 4492)
            case 0x0017: return "secp256r1";
            case 0x0018: return "secp384r1";
            case 0x0019: return "secp521r1";
            case 0x001D: return "x25519";
            case 0x001E: return "x448";
            case 0x0100: return "ffdhe2048";
            case 0x0101: return "ffdhe3072";
            default:     return String.format("0x%04X", id);
        }
    }

    /**
     * Decodes a handshake type byte to a readable string.
     * Based on IANA TLS HandshakeType registry:
     * https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7
     * 
     * @param value The handshake type byte
     * @return Readable handshake type name with description and version context
     */
    private String decodeHandshakeType(byte value) {
        switch (value & 0xFF) {
            // 0: Reserved / Legacy
            case 0:   return "hello_request_RESERVED (0) - Used in TLS < 1.3";
            
            // 1-2: Core handshake messages
            case 1:   return "client_hello (1) - Client initiates handshake";
            case 2:   return "server_hello (2) - Server responds with parameters";
            
            // 3: DTLS specific
            case 3:   return "hello_verify_request_RESERVED (3) - DTLS only (moved)";
            
            // 4: Session management
            case 4:   return "new_session_ticket (4) - Session resumption ticket";
            
            // 5: TLS 1.3 early data
            case 5:   return "end_of_early_data (5) - TLS 1.3: marks end of early data";
            
            // 6: Replaced by extension
            case 6:   return "hello_retry_request_RESERVED (6) - Replaced by extension in TLS 1.3";
            
            // 7: Unassigned
            case 7:   return "UNASSIGNED (7)";
            
            // 8: TLS 1.3 encrypted extensions
            case 8:   return "encrypted_extensions (8) - TLS 1.3 encrypted server extensions";
            
            // 9-10: Connection ID (DTLS)
            case 9:   return "request_connection_id (9) - DTLS connection ID request";
            case 10:  return "new_connection_id (10) - DTLS new connection ID";
            
            // 11: Certificate message
            case 11:  return "certificate (11) - Certificate transmission";
            
            // 12: Legacy key exchange
            case 12:  return "server_key_exchange_RESERVED (12) - Used in TLS < 1.3";
            
            // 13: Certificate request
            case 13:  return "certificate_request (13) - Request client certificate";
            
            // 14: Legacy server done
            case 14:  return "server_hello_done_RESERVED (14) - Used in TLS < 1.3";
            
            // 15: Certificate verification
            case 15:  return "certificate_verify (15) - Certificate signature verification";
            
            // 16: Legacy client key exchange
            case 16:  return "client_key_exchange_RESERVED (16) - Used in TLS < 1.3";
            
            // 17: Client certificate request
            case 17:  return "client_certificate_request (17) - Used in TLS < 1.3";
            
            // 18-19: Unassigned
            case 18:  return "UNASSIGNED (18)";
            case 19:  return "UNASSIGNED (19)";
            
            // 20: Finished message
            case 20:  return "finished (20) - Handshake completion verification";
            
            // 21-23: Legacy features
            case 21:  return "certificate_url_RESERVED (21) - Used in TLS < 1.3";
            case 22:  return "certificate_status_RESERVED (22) - OCSP stapling (TLS < 1.3)";
            case 23:  return "supplemental_data_RESERVED (23) - Used in TLS < 1.3";
            
            // 24: Key update (TLS 1.3 post-handshake)
            case 24:  return "key_update (24) - TLS 1.3: update cipher keys";
            
            // 25: Compressed certificate
            case 25:  return "compressed_certificate (25) - Compressed certificate (RFC 8879)";
            
            // 26: External key token
            case 26:  return "ekt_key (26) - External key token (RFC 8870)";
            
            // 27-253: Unassigned range
            // Note: Values 27-253 are unassigned per IANA registry
            
            // 254: Special message hash
            case 254: return "message_hash (254) - Contains hash of transcript";
            
            // 255: Unassigned
            case 255: return "UNASSIGNED (255)";
            
            default:  return String.format("Unknown handshake type (%d)", value & 0xFF);
        }
    }

    /**
     * Decodes an alert level byte to a readable string.
     * 
     * @param value The alert level byte
     * @return "warning", "fatal", or "unknown"
     */
    private String decodeAlertLevel(byte value) {
        switch (value & 0xFF) {
            case 1:  return "warning (1)";
            case 2:  return "fatal (2)";
            default: return String.format("Unknown (%d)", value & 0xFF);
        }
    }

    
    /**
     * from : https://www.gnutls.org/manual/html_node/The-TLS-Alert-Protocol.html
     * 
     * Decodes an alert description byte to a readable string.
     * Maps all standard TLS alert codes to their RFC names and descriptions.
     * Based on GnuTLS documentation and RFC 8446 (TLS 1.3).
     * 
     * @param value The alert description byte
     * @return Readable alert description with optional additional context
     */
    private String decodeAlertDescription(byte value) {
        switch (value & 0xFF) {
            // Successful/Informational alerts
            case 0:   return "close_notify (0) - Connection closed cleanly";
            
            // Unexpected message alerts (10-19)
            case 10:  return "unexpected_message (10) - Received unexpected message";
            
            // Bad record MAC alerts (20-29)
            case 20:  return "bad_record_mac (20) - Invalid MAC (TLS 1.2 and below)";
            case 21:  return "decryption_failed (21) - Decryption failed (deprecated)";
            case 22:  return "record_overflow (22) - Record overflow";
            
            // Decompression failure alerts (30-39)
            case 30:  return "decompression_failure (30) - Decompression failed (deprecated)";
            
            // Handshake failure alerts (40-49)
            case 40:  return "handshake_failure (40) - Handshake failed";
            case 41:  return "no_certificate_SSL3 (41) - No certificate (SSL 3.0 only)";
            case 42:  return "bad_certificate (42) - Certificate is corrupted or invalid";
            case 43:  return "unsupported_certificate (43) - Certificate type not supported";
            case 44:  return "certificate_revoked (44) - Certificate was revoked";
            case 45:  return "certificate_expired (45) - Certificate has expired";
            case 46:  return "certificate_unknown (46) - Unknown certificate";
            case 47:  return "illegal_parameter (47) - Illegal parameter";
            case 48:  return "unknown_ca (48) - Unknown Certificate Authority";
            case 49:  return "access_denied (49) - Access denied";
            
            // Decode/decrypt error alerts (50-59)
            case 50:  return "decode_error (50) - Decode error";
            case 51:  return "decrypt_error (51) - Decrypt error";
            
            // Export restriction alerts (60-69)
            case 60:  return "export_restriction (60) - Export restriction (deprecated)";
            
            // Protocol version alerts (70-79)
            case 70:  return "protocol_version (70) - Protocol version mismatch";
            case 71:  return "insufficient_security (71) - Insufficient security level";
            
            // Internal error alerts (80-89)
            case 80:  return "internal_error (80) - Internal implementation error";
            case 86:  return "inappropriate_fallback (86) - Inappropriate fallback (RFC 7507)";
            
            // User/cancel alerts (90-99)
            case 90:  return "user_canceled (90) - User canceled operation";
            
            // No renegotiation alerts (100-108)
            case 100: return "no_renegotiation (100) - No renegotiation allowed";
            
            // Extension-related alerts (109-114)
            case 109: return "missing_extension (109) - Required extension missing";
            case 110: return "unsupported_extension (110) - Unsupported extension sent";
            case 111: return "certificate_unobtainable (111) - Certificate unobtainable";
            case 112: return "unrecognized_name (112) - Server name not recognized (SNI)";
            
            // PSK/identity alerts (115)
            case 115: return "unknown_psk_identity (115) - Unknown PSK/SRP identity";
            
            // Certificate requirement alerts (116-119)
            case 116: return "certificate_required (116) - Certificate required";
            
            // Application protocol alerts (120-129)
            case 120: return "no_application_protocol (120) - No ALPN protocol negotiated";
            
            // Unknown/unsupported codes
            default:  return String.format("Unknown alert (%d)", value & 0xFF);
        }
    }

    /**
     * Converts a byte array to a clean hexadecimal string (no spaces, no brackets).
     * 
     * @param bytes The byte array to convert
     * @return Hexadecimal string representation (uppercase, no delimiter)
     */
    private String toCleanHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b & 0xFF));
        }
        return sb.toString();
    }
}