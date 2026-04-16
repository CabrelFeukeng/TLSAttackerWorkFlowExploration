package enums;

//Ref : soure pour les correspondances : https://wiki.mozilla.org/Security/Cipher_Suites
public enum CipherSuiteC {
	
	 // TLS 1.3 (0x0304)
	 // Ref: https://docs.openssl.org/master/man1/openssl-ciphers/#tls-v13-cipher-suites
	 TLS_AES_128_GCM_SHA256                     ("TLS_AES_128_GCM_SHA256",                 true), // 0x1301
	 TLS_AES_256_GCM_SHA384                     ("TLS_AES_256_GCM_SHA384",                 true), // 0x1302
	 TLS_CHACHA20_POLY1305_SHA256               ("TLS_CHACHA20_POLY1305_SHA256",           true), // 0x1303
	 TLS_AES_128_CCM_SHA256                     ("TLS_AES_128_CCM_SHA256",                 true), // 0x1304
	 TLS_AES_128_CCM_8_SHA256                   ("TLS_AES_128_CCM_8_SHA256",               true), // 0x1305
    
	// TLS 1.2 - AEAD ciphers (GCM) (0x0303)
	// Ref: https://docs.openssl.org/master/man1/openssl-ciphers/#aes-cipher-suites-for-tls-v12
	TLS_RSA_WITH_AES_128_GCM_SHA256            ("AES128-GCM-SHA256",                      false),
	TLS_RSA_WITH_AES_256_GCM_SHA384            ("AES256-GCM-SHA384",                      false),
	TLS_DHE_RSA_WITH_AES_128_GCM_SHA256        ("DHE-RSA-AES128-GCM-SHA256",              false),
	TLS_DHE_RSA_WITH_AES_256_GCM_SHA384        ("DHE-RSA-AES256-GCM-SHA384",              false),
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256      ("ECDHE-RSA-AES128-GCM-SHA256",            false),
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384      ("ECDHE-RSA-AES256-GCM-SHA384",            false),
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256    ("ECDHE-ECDSA-AES128-GCM-SHA256",          false),
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384    ("ECDHE-ECDSA-AES256-GCM-SHA384",          false),
	 
	// TLS 1.2 - CBC mode ciphers
	TLS_RSA_WITH_AES_128_CBC_SHA256            ("AES128-SHA256",                          false),
	TLS_RSA_WITH_AES_256_CBC_SHA256            ("AES256-SHA256",                          false),
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA256        ("DHE-RSA-AES128-SHA256",                  false),
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA256        ("DHE-RSA-AES256-SHA256",                  false),
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256      ("ECDHE-RSA-AES128-SHA256",                false),
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384      ("ECDHE-RSA-AES256-SHA384",                false),
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256    ("ECDHE-ECDSA-AES128-SHA256",              false),
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384    ("ECDHE-ECDSA-AES256-SHA384",              false),
	
	// TLS 1.2 - ChaCha20-Poly1305 ciphers
	// Ref: https://docs.openssl.org/master/man1/openssl-ciphers/#chacha20-poly1305-cipher-suites-extending-tls-v12
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256     ("ECDHE-RSA-CHACHA20-POLY1305",         false),
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256   ("ECDHE-ECDSA-CHACHA20-POLY1305",       false),
	TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256       ("DHE-RSA-CHACHA20-POLY1305",           false),
	
	// TLS 1.2 - Legacy ciphers (3DES, etc.)
	TLS_RSA_WITH_3DES_EDE_CBC_SHA              ("DES-CBC3-SHA",                           false),
	TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA          ("DHE-RSA-DES-CBC3-SHA",                   false),
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA        ("ECDHE-RSA-DES-CBC3-SHA",                 false),
	TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA      ("ECDHE-ECDSA-DES-CBC3-SHA",               false);
	
    private final String opensslName;
    private final boolean tls13;

    CipherSuiteC(String opensslName, boolean tls13) {
        this.opensslName = opensslName;
        this.tls13 = tls13;
    }

    public String opensslName() { return opensslName; }
    public boolean isTls13()    { return tls13; }
}
