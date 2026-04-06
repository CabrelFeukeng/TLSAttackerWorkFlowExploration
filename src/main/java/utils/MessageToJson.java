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

public class MessageToJson {
	
	private WorkflowTrace trace;

    private static final Logger LOGGER = LogManager.getLogger(MessageToJson.class);

    private static final String DEFAULT_OUTPUT_DIR = "src/main/ressources/messages/";

    public MessageToJson(WorkflowTrace trace) {
    	this.trace = trace;
    }
    
    public void informationsExtraction(String TSL_Version) {
    	
    	List<TlsAction> actions = trace.getTlsActions();
    	for (int i = 0; i < actions.size(); i++) {
    		
    		TlsAction action = actions.get(i);
    		List<ProtocolMessage> messages = resolveMessages(action);
    		if (messages != null && !messages.isEmpty()) {
	            for (ProtocolMessage msg : messages) {
	            	toJson(msg, null, TSL_Version);
	            }
	        }
    	}
    	
    }
    
    private List<ProtocolMessage> resolveMessages(TlsAction action) {
	    if (action instanceof SendAction) {
	        List<ProtocolMessage> sent = ((SendAction) action).getSentMessages();
	        if (sent != null && !sent.isEmpty()) return sent;
	        return ((SendAction) action).getConfiguredMessages();
	    }
	    if (action instanceof ReceiveAction) {
	        List<ProtocolMessage> received = ((ReceiveAction) action).getReceivedMessages();
	        if (received != null && !received.isEmpty()) return received;
	        return ((ReceiveAction) action).getExpectedMessages();
	    }
	    return Collections.emptyList();
	}


    public void toJson(ProtocolMessage message, String outputPath, String TLS_Version) {
        String resolvedPath = (outputPath != null)
            ? outputPath
            : resolveOutputPath(message, TLS_Version);
        ensureFileExists(resolvedPath, message);
        writeToFile(buildJson(message), resolvedPath);
    }


    private String resolveOutputPath(ProtocolMessage message, String TLS_Version) {
        String messageType = message.getClass().getSimpleName();
        return DEFAULT_OUTPUT_DIR + TLS_Version + "/" + messageType + ".json";
    }
    
    

    private void ensureFileExists(String outputPath, ProtocolMessage message) {
        File file = new File(outputPath);
        File parentDir = file.getParentFile();

        if (parentDir != null && !parentDir.exists()) {
            if (parentDir.mkdirs()) {
                LOGGER.info("Dossier créé : {}", parentDir.getAbsolutePath());
            } else {
                LOGGER.error("Impossible de créer le dossier : {}", parentDir.getAbsolutePath());
                return;
            }
        }

        if (!file.exists()) {
            try {
                if (file.createNewFile()) {
                    LOGGER.info("Fichier créé pour {} : {}",
                        message.getClass().getSimpleName(), file.getAbsolutePath());
                }
            } catch (IOException e) {
                LOGGER.error("Impossible de créer le fichier : {}", outputPath, e);
            }
        } else {
            LOGGER.warn("Le fichier existe déjà, il sera écrasé : {}", outputPath);
        }
    }

    private void writeToFile(JsonObject json, String outputPath) {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        try (FileWriter writer = new FileWriter(outputPath)) {
            gson.toJson(json, writer);
            LOGGER.info("Message écrit dans : {}", outputPath);
        } catch (IOException e) {
            LOGGER.error("Erreur lors de l'écriture du fichier JSON : {}", outputPath, e);
        }
    }


    private JsonObject buildJson(ProtocolMessage message) {
        JsonObject json = new JsonObject();
        json.addProperty("messageClass", message.getClass().getSimpleName());
        json.addProperty("timestamp", LocalDateTime.now().toString());

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
            LOGGER.warn("Type de message non géré : {}", message.getClass().getSimpleName());
            json.addProperty("warning", "Type de message non géré explicitement");
        }

        return json;
    }


    private void serializeClientHello(ClientHelloMessage m, JsonObject json) {
        addHandshakeHeader(m, json);

        if (m.getProtocolVersion() != null && m.getProtocolVersion().getValue() != null) {
            json.addProperty("legacyVersion",
                decodeProtocolVersion(m.getProtocolVersion().getValue()));
        }
        if (m.getRandom() != null && m.getRandom().getValue() != null) {
            json.addProperty("clientRandom", toCleanHex(m.getRandom().getValue()));
        }
        if (m.getSessionIdLength() != null && m.getSessionIdLength().getValue() != null) {
            json.addProperty("legacySessionIdLength", m.getSessionIdLength().getValue());
        }
        if (m.getSessionId() != null && m.getSessionId().getValue() != null
                && m.getSessionId().getValue().length > 0) {
            json.addProperty("legacySessionId", toCleanHex(m.getSessionId().getValue()));
        }
        if (m.getCipherSuiteLength() != null && m.getCipherSuiteLength().getValue() != null) {
            json.addProperty("cipherSuiteLength", m.getCipherSuiteLength().getValue());
        }
        if (m.getCipherSuites() != null && m.getCipherSuites().getValue() != null) {
            json.add("cipherSuites", decodeCipherSuiteList(m.getCipherSuites().getValue()));
        }
        if (m.getCompressionLength() != null && m.getCompressionLength().getValue() != null) {
            json.addProperty("legacyCompressionMethodsLength", m.getCompressionLength().getValue());
        }
        if (m.getCompressions() != null && m.getCompressions().getValue() != null) {
            json.addProperty("legacyCompressionMethods",
                m.getCompressions().getValue()[0] == 0 ? "none (0x00)" : toCleanHex(m.getCompressions().getValue()));
        }

        boolean hasEch = m.getExtensions() != null && m.getExtensions().stream()
            .anyMatch(e -> e instanceof EncryptedClientHelloExtensionMessage);
        json.addProperty("encryptedClientHello", hasEch);

        serializeExtensions(m, json);
    }

    private void serializeServerHello(ServerHelloMessage m, JsonObject json) {
        addHandshakeHeader(m, json);

        if (m.getProtocolVersion() != null && m.getProtocolVersion().getValue() != null) {
            json.addProperty("selectedVersion",
                decodeProtocolVersion(m.getProtocolVersion().getValue()));
        }
        if (m.getRandom() != null && m.getRandom().getValue() != null) {
            json.addProperty("serverRandom", toCleanHex(m.getRandom().getValue()));
        }
        if (m.getSessionIdLength() != null && m.getSessionIdLength().getValue() != null) {
            json.addProperty("legacySessionIdLength", m.getSessionIdLength().getValue());
        }
        if (m.getSessionId() != null && m.getSessionId().getValue() != null
                && m.getSessionId().getValue().length > 0) {
            json.addProperty("legacySessionId", toCleanHex(m.getSessionId().getValue()));
        }
        if (m.getSelectedCipherSuite() != null && m.getSelectedCipherSuite().getValue() != null) {
            json.addProperty("selectedCipherSuite",
                decodeCipherSuite(m.getSelectedCipherSuite().getValue()));
        }
        if (m.getSelectedCompressionMethod() != null
                && m.getSelectedCompressionMethod().getValue() != null) {
            json.addProperty("selectedCompressionMethod",
                m.getSelectedCompressionMethod().getValue() == 0
                    ? "none (0x00)"
                    : String.format("0x%02X", m.getSelectedCompressionMethod().getValue()));
        }

        serializeExtensions(m, json);
    }

    private void serializeCertificate(CertificateMessage m, JsonObject json) {
        addHandshakeHeader(m, json);

        if (m.getCertificatesListLength() != null && m.getCertificatesListLength().getValue() != null) {
            json.addProperty("certificatesListLength", m.getCertificatesListLength().getValue());
        }
        if (m.getCertificatesListBytes() != null && m.getCertificatesListBytes().getValue() != null) {
            json.addProperty("certificatesListBytes",
                toCleanHex(m.getCertificatesListBytes().getValue()));
        }
    }

    private void serializeCertificateVerify(CertificateVerifyMessage m, JsonObject json) {
        addHandshakeHeader(m, json);

        if (m.getSignatureHashAlgorithm() != null && m.getSignatureHashAlgorithm().getValue() != null) {
            json.addProperty("signatureHashAlgorithm",
                decodeSignatureAlgorithm(m.getSignatureHashAlgorithm().getValue()));
        }
        if (m.getSignatureLength() != null && m.getSignatureLength().getValue() != null) {
            json.addProperty("signatureLength", m.getSignatureLength().getValue());
        }
        if (m.getSignature() != null && m.getSignature().getValue() != null) {
            json.addProperty("signature", toCleanHex(m.getSignature().getValue()));
        }
    }

    private void serializeFinished(FinishedMessage m, JsonObject json) {
        addHandshakeHeader(m, json);

        if (m.getVerifyData() != null && m.getVerifyData().getValue() != null) {
            json.addProperty("verifyData", toCleanHex(m.getVerifyData().getValue()));
        }
    }

    private void serializeAlert(AlertMessage m, JsonObject json) {
        if (m.getLevel() != null && m.getLevel().getValue() != null) {
            json.addProperty("alertLevel", decodeAlertLevel(m.getLevel().getValue()));
        }
        if (m.getDescription() != null && m.getDescription().getValue() != null) {
            json.addProperty("alertDescription", decodeAlertDescription(m.getDescription().getValue()));
        }
    }

    private void serializeApplication(ApplicationMessage m, JsonObject json) {
        if (m.getData() != null && m.getData().getValue() != null) {
            json.addProperty("applicationData", toCleanHex(m.getData().getValue()));
        }
    }



    private void addHandshakeHeader(HandshakeMessage m, JsonObject json) {
        if (m.getType() != null && m.getType().getValue() != null) {
            json.addProperty("handshakeType",
                decodeHandshakeType(m.getType().getValue()));
        }
        if (m.getLength() != null && m.getLength().getValue() != null) {
            json.addProperty("handshakeLength", m.getLength().getValue());
        }
    }

    private void serializeExtensions(HandshakeMessage m, JsonObject json) {
        if (m.getExtensionBytes() != null && m.getExtensionBytes().getValue() != null) {
            json.addProperty("extensionsTotalLength", m.getExtensionBytes().getValue().length);
        }
        if (m.getExtensions() != null && !m.getExtensions().isEmpty()) {
            JsonArray extensionsArray = new JsonArray();
            for (ExtensionMessage ext : m.getExtensions()) {
                JsonObject extJson = new JsonObject();

                byte[] typeBytes = ext.getExtensionType() != null
                    ? ext.getExtensionType().getValue() : null;

                extJson.addProperty("extensionName", decodeExtensionType(typeBytes));

                if (ext.getExtensionLength() != null && ext.getExtensionLength().getValue() != null) {
                    extJson.addProperty("extensionLength", ext.getExtensionLength().getValue());
                }
                if (ext.getExtensionContent() != null && ext.getExtensionContent().getValue() != null) {
                    extJson.addProperty("extensionContent",
                        decodeExtensionContent(typeBytes, ext.getExtensionContent().getValue()));
                }

                extensionsArray.add(extJson);
            }
            json.add("extensions", extensionsArray);
        } else {
            json.addProperty("extensions", "AUCUNE EXTENSION");
        }
    }


    private String decodeProtocolVersion(byte[] bytes) {
        if (bytes == null || bytes.length < 2) return "inconnu";
        for (ProtocolVersion v : ProtocolVersion.values()) {
            if (Arrays.equals(v.getValue(), bytes)) {
                return v.name().replace("_", " ")
                    + String.format(" (0x%02X%02X)", bytes[0] & 0xFF, bytes[1] & 0xFF);
            }
        }
        return String.format("Inconnu (0x%02X%02X)", bytes[0] & 0xFF, bytes[1] & 0xFF);
    }

    private String decodeCipherSuite(byte[] bytes) {
        if (bytes == null || bytes.length < 2) return "inconnue";
        for (CipherSuite cs : CipherSuite.values()) {
            if (Arrays.equals(cs.getByteValue(), bytes)) {
                return cs.name();
            }
        }
        return String.format("Inconnue (0x%02X%02X)", bytes[0] & 0xFF, bytes[1] & 0xFF);
    }

    /** Décode une liste de cipher suites (paires de 2 bytes) en JsonArray lisible. */
    private JsonArray decodeCipherSuiteList(byte[] bytes) {
        JsonArray array = new JsonArray();
        if (bytes == null) return array;
        for (int i = 0; i + 1 < bytes.length; i += 2) {
            array.add(decodeCipherSuite(new byte[]{bytes[i], bytes[i + 1]}));
        }
        return array;
    }

    private String decodeExtensionType(byte[] bytes) {
        if (bytes == null || bytes.length < 2) return "inconnu";
        for (ExtensionType type : ExtensionType.values()) {
            if (Arrays.equals(type.getValue(), bytes)) {
                return type.name().toLowerCase();
            }
        }
        return String.format("Inconnu (0x%02X%02X)", bytes[0] & 0xFF, bytes[1] & 0xFF);
    }

    private String decodeExtensionContent(byte[] typeBytes, byte[] contentBytes) {
        if (contentBytes == null) return "";
        if (typeBytes == null) return toCleanHex(contentBytes);

        for (ExtensionType type : ExtensionType.values()) {
            if (!Arrays.equals(type.getValue(), typeBytes)) continue;
            switch (type) {
                case SUPPORTED_VERSIONS:
                    return decodeVersionList(contentBytes);
                case KEY_SHARE:
                    return decodeKeyShare(contentBytes);
                case SIGNATURE_AND_HASH_ALGORITHMS:
                    return decodeSignatureAlgorithmList(contentBytes);
                default:
                    return toCleanHex(contentBytes);
            }
        }
        return toCleanHex(contentBytes);
    }

    private String decodeVersionList(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return "";
        // ServerHello : 2 bytes = une seule version
        if (bytes.length == 2) return decodeProtocolVersion(bytes);
        // ClientHello : 1 byte de longueur + liste
        StringBuilder sb = new StringBuilder();
        int start = (bytes.length % 2 == 1) ? 1 : 0;
        for (int i = start; i + 1 < bytes.length; i += 2) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(decodeProtocolVersion(new byte[]{bytes[i], bytes[i + 1]}));
        }
        return sb.toString();
    }

    private String decodeKeyShare(byte[] bytes) {
        if (bytes == null || bytes.length < 4) return toCleanHex(bytes);
        int groupId = ((bytes[0] & 0xFF) << 8) | (bytes[1] & 0xFF);
        int keyLen  = ((bytes[2] & 0xFF) << 8) | (bytes[3] & 0xFF);
        byte[] key  = Arrays.copyOfRange(bytes, 4, Math.min(4 + keyLen, bytes.length));
        return String.format("namedGroup=%s, keyLength=%d, publicKey=%s",
            decodeNamedGroup(groupId), keyLen, toCleanHex(key));
    }

    private String decodeSignatureAlgorithmList(byte[] bytes) {
        if (bytes == null || bytes.length < 2) return toCleanHex(bytes);
        StringBuilder sb = new StringBuilder();
        // 2 premiers bytes = longueur totale de la liste, on les saute
        for (int i = 2; i + 1 < bytes.length; i += 2) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(decodeSignatureAlgorithm(new byte[]{bytes[i], bytes[i + 1]}));
        }
        return sb.toString();
    }

    private String decodeSignatureAlgorithm(byte[] bytes) {
        if (bytes == null || bytes.length < 2) return "inconnu";
        int id = ((bytes[0] & 0xFF) << 8) | (bytes[1] & 0xFF);
        switch (id) {
            case 0x0401: return "rsa_pkcs1_sha256";
            case 0x0501: return "rsa_pkcs1_sha384";
            case 0x0601: return "rsa_pkcs1_sha512";
            case 0x0403: return "ecdsa_secp256r1_sha256";
            case 0x0503: return "ecdsa_secp384r1_sha384";
            case 0x0603: return "ecdsa_secp521r1_sha512";
            case 0x0804: return "rsa_pss_rsae_sha256";
            case 0x0805: return "rsa_pss_rsae_sha384";
            case 0x0806: return "rsa_pss_rsae_sha512";
            case 0x0201: return "rsa_pkcs1_sha1";
            case 0x0203: return "ecdsa_sha1";
            default:     return String.format("Inconnu (0x%04X)", id);
        }
    }

    private String decodeNamedGroup(int id) {
        switch (id) {
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

    private String decodeHandshakeType(byte value) {
        switch (value & 0xFF) {
            case 1:  return "ClientHello (1)";
            case 2:  return "ServerHello (2)";
            case 4:  return "NewSessionTicket (4)";
            case 8:  return "EncryptedExtensions (8)";
            case 11: return "Certificate (11)";
            case 13: return "CertificateRequest (13)";
            case 15: return "CertificateVerify (15)";
            case 20: return "Finished (20)";
            default: return String.format("Inconnu (%d)", value & 0xFF);
        }
    }

    private String decodeAlertLevel(byte value) {
        switch (value & 0xFF) {
            case 1:  return "warning (1)";
            case 2:  return "fatal (2)";
            default: return String.format("Inconnu (%d)", value & 0xFF);
        }
    }

    private String decodeAlertDescription(byte value) {
        switch (value & 0xFF) {
            case 0:   return "close_notify";
            case 10:  return "unexpected_message";
            case 20:  return "bad_record_mac";
            case 40:  return "handshake_failure";
            case 42:  return "bad_certificate";
            case 44:  return "certificate_expired";
            case 45:  return "certificate_unknown";
            case 47:  return "illegal_parameter";
            case 48:  return "unknown_ca";
            case 50:  return "decode_error";
            case 51:  return "decrypt_error";
            case 70:  return "protocol_version";
            case 80:  return "internal_error";
            case 86:  return "inappropriate_fallback";
            case 100: return "no_renegotiation";
            case 109: return "missing_extension";
            case 110: return "unsupported_extension";
            case 116: return "certificate_required";
            case 120: return "no_application_protocol";
            default:  return String.format("Inconnu (%d)", value & 0xFF);
        }
    }

    private String toCleanHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b & 0xFF));
        }
        return sb.toString();
    }
}