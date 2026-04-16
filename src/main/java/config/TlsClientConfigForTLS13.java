package config;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;

public class TlsClientConfigForTLS13 implements TlsClientConfig{
	
	private final String HOST = GlobalConfig.HOST;
	private final int PORT = GlobalConfig.PORT;
	private static TlsClientConfigForTLS13 instance;
	
    private TlsClientConfigForTLS13() {} 
    
    public static TlsClientConfigForTLS13 getInstance() {
        if (instance == null) {
            instance = new TlsClientConfigForTLS13();
        }
        return instance;
    }
    

	public Config build() {

	    Config config = new Config();
	    
        config.setDefaultRunningMode(RunningModeType.CLIENT);
        
        config.setDefaultClientConnection(new OutboundConnection(HOST, PORT));

        config.setWorkflowExecutorShouldClose(true);
        
        // IMPORTANT: Enable all necessary layers
        config.setAddECPointFormatExtension(true);
        config.setAddEllipticCurveExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddSupportedVersionsExtension(true);
        config.setAddKeyShareExtension(true);
        
        // Configure protocol version
        config.setHighestProtocolVersion(ProtocolVersion.TLS13);
        config.setSupportedVersions(ProtocolVersion.TLS13);
	    config.setDefaultSelectedProtocolVersion(ProtocolVersion.TLS13);


	    // TLS 1.3 cipher suites
	    config.setDefaultClientSupportedCipherSuites(
	        CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
	        CipherSuite.TLS_AES_128_GCM_SHA256,
	        CipherSuite.TLS_AES_128_CCM_8_SHA256,
	        CipherSuite.TLS_AES_128_CCM_SHA256,
	        CipherSuite.TLS_SM4_GCM_SM3,
	        CipherSuite.TLS_SM4_CCM_SM3
	    );
	    

	    // Elliptic curve groups for ECDHE key share
	    config.setDefaultClientKeyShareNamedGroups(
	        NamedGroup.ECDH_X25519,
	        NamedGroup.SECP256R1
	    );

	    // Accepted signature algorithms
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(
                SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256,
                SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA384,
                SignatureAndHashAlgorithm.ECDSA_SHA256,
                SignatureAndHashAlgorithm.ED25519  
            );

	    config.setStopActionsAfterFatal(true);
	    config.setStopReceivingAfterFatal(true);
	    config.setEnforceSettings(true);

	    return config;
	}
	
	 public String getHost() { return HOST; }
	 public int getPort()    { return PORT; }
	 public String getTlsVersion() {return "TLS_13";}
}






