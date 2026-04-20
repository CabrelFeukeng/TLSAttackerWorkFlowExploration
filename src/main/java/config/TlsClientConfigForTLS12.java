package config;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;

public class TlsClientConfigForTLS12 implements TlsClientConfig {

    private final String HOST = GlobalConfig.HOST;
    private final int    PORT = GlobalConfig.PORT;

    private static TlsClientConfigForTLS12 instance;
    private CipherSuite[] cipherSuites;
	private SignatureAndHashAlgorithm[] signatureAndHashAlgorithms;
	private NamedGroup[] ClientKeyShareNamedGroups;

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
        		cipherSuites
        );

        // Groupes ECDHE — doit inclure SECP256R1 (= prime256v1 côté serveur)
        config.setDefaultClientNamedGroups(
            NamedGroup.SECP256R1,
            NamedGroup.SECP384R1
        );

        // Algorithmes de signature TLS 1.2 
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
    public String getTlsVersion() {return "TLS_12";}

	public CipherSuite[] getCipherSuites() {
		return cipherSuites;
	}

	public void setCipherSuites(CipherSuite[] cipherSuites) {
		this.cipherSuites = cipherSuites;
	}

	public SignatureAndHashAlgorithm[] getSignatureAndHashAlgorithms() {
		return signatureAndHashAlgorithms;
	}

	public void setSignatureAndHashAlgorithms(SignatureAndHashAlgorithm[] signatureAndHashAlgorithms) {
		this.signatureAndHashAlgorithms = signatureAndHashAlgorithms;
	}

	public NamedGroup[] getClientKeyShareNamedGroups() {
		return ClientKeyShareNamedGroups;
	}

	public void setClientKeyShareNamedGroups(NamedGroup[] clientKeyShareNamedGroups) {
		ClientKeyShareNamedGroups = clientKeyShareNamedGroups;
	}

	
}