package config;

import java.util.List;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import enums.CipherSuiteC;

public class GlobalConfig {
	
	public static final String CERTIFICATE_PATH = "src/main/resources/data/server.crt";
	public static final String KEY_PATH = "src/main/resources/data/server.key";
	public static final String HOST = "localhost";
	public static final int PORT = 1234;
	public static final String DEFAULT_JSON_OUTPUT_DIR = "src/main/resources/messages/";  // Default output directory for JSON files

	
	///////////////////--------------------------------TLS 1.3 
	//-- OK
	public static final CipherSuite[] TLS13ClientCipherSuitesOK = {
			CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
	        CipherSuite.TLS_AES_128_GCM_SHA256,
	        CipherSuite.TLS_AES_128_CCM_8_SHA256,
	        CipherSuite.TLS_AES_128_CCM_SHA256,
    };
	
	public static final List<CipherSuiteC> TLS13ServerCipherSuitesOK = List.of(
	        CipherSuiteC.TLS_AES_128_CCM_SHA256,
	        CipherSuiteC.TLS_AES_128_CCM_8_SHA256);
	
	//-- Case KO
	public static final CipherSuite[] TLS13ClientCipherSuitesKO = {
			CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
	        CipherSuite.TLS_AES_128_GCM_SHA256,
    };
	
	public static final List<CipherSuiteC> TLS13ServerCipherSuitesKO = List.of(
			CipherSuiteC.TLS_AES_128_CCM_SHA256,
	        CipherSuiteC.TLS_AES_128_CCM_8_SHA256);
	
	
	///////////////////--------------------------------TLS 1.2
	//-- OK
	public static final CipherSuite[] TLS12ClientCipherSuitesOK = {
			CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
	};
	
	public static final List<CipherSuiteC> TLS12ServerCipherSuitesOK = List.of(
			CipherSuiteC.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
			CipherSuiteC.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
	
	
	//-- Case KO
	public static final CipherSuite[] TLS12ClientCipherSuitesKO = {
			CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
			};
	
	public static final List<CipherSuiteC> TLS12ServerCipherSuitesKO = List.of(
			CipherSuiteC.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			CipherSuiteC.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
	
	}
