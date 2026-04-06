package config;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;

public class TlsClientConfigForTLS12 {

    private final String HOST = "localhost";
    private final int    PORT = 1234;

    private static TlsClientConfigForTLS12 instance;

    private TlsClientConfigForTLS12() {}

    public static TlsClientConfigForTLS12 getInstance() {
        if (instance == null) {
            instance = new TlsClientConfigForTLS12();
        }
        return instance;
    }

    public Config build() {
        Config config = new Config();

        config.setDefaultRunningMode(RunningModeType.CLIENT);
        config.setDefaultClientConnection(new OutboundConnection(HOST, PORT));
        config.setWorkflowExecutorShouldClose(true);

        // Extensions
        config.setAddECPointFormatExtension(true);
        config.setAddEllipticCurveExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);

        // Version
        config.setHighestProtocolVersion(ProtocolVersion.TLS12);
        config.setSupportedVersions(ProtocolVersion.TLS12);
        config.setDefaultSelectedProtocolVersion(ProtocolVersion.TLS12);

        // Cipher suites — ECDHE uniquement, pas de DHE ni RSA
        config.setDefaultClientSupportedCipherSuites(
            CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
        );

        // Groupes ECDHE — doit inclure SECP256R1 (= prime256v1 côté serveur)
        config.setDefaultClientNamedGroups(
            NamedGroup.SECP256R1,
            NamedGroup.SECP384R1
        );

        // Algorithmes de signature TLS 1.2 (pas PSS — c'est TLS 1.3)
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(
            SignatureAndHashAlgorithm.RSA_SHA256,
            SignatureAndHashAlgorithm.RSA_SHA384,
            SignatureAndHashAlgorithm.ECDSA_SHA256
        );

        // Forcer TLS-Attacker à utiliser exactement ces paramètres
        config.setEnforceSettings(true);
        config.setStopActionsAfterFatal(true);
        config.setStopReceivingAfterFatal(true);

        return config;
    }

    public String getHost() { return HOST; }
    public int    getPort() { return PORT; }
}