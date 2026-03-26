package config;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.*;


/*
 * TLS client configuration
 */
public class TlsClientConfig {
	
	private final String host = "localhost";
	private final int port = 1234;
	private static TlsClientConfig instance;

    
    private TlsClientConfig() {} 
    
    public static TlsClientConfig getInstance() {
        if (instance == null) {
            instance = new TlsClientConfig();
        }
        return instance;
    }
	
	
	@SuppressWarnings("deprecation")
	public Config buid() {
		Config config = Config.createConfig();
		OutboundConnection connection = new OutboundConnection(host, port);
		config.setDefaultClientConnection(connection);
		
		//config.getDefaultClientConnection().setHostname(host);
		//config.getDefaultClientConnection().setPort(port);
		
		config.setHighestProtocolVersion(ProtocolVersion.TLS13);
		config.setDefaultSelectedProtocolVersion(ProtocolVersion.TLS13);
		
		config.setDefaultClientSupportedCipherSuites(
				CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
	            CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
	            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
				);
		
		
        config.setQuic(true);
        config.setStopActionsAfterFatal(true);
        config.setStopReceivingAfterFatal(true);

		
		return config;
	}
	
	
	 public String getHost() { return host; }
	 public int getPort()    { return port; }

}
