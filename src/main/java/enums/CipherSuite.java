package enums;

public enum CipherSuite {
    // --- TLS 1.3 ---
    TLS_AES_256_GCM_SHA384          ("TLS_AES_256_GCM_SHA384",           true),
    TLS_AES_128_GCM_SHA256          ("TLS_AES_128_GCM_SHA256",           true),
    TLS_CHACHA20_POLY1305_SHA256    ("TLS-CHACHA20-POLY1305-SHA256",      true),

    //TLS1.2
    TLS_RSA_WITH_AES_128_GCM_SHA256 ("AES128-GCM-SHA256", false),
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 ("DHE-RSA-AES256-GCM-SHA384", false),
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ("ECDHE-RSA-AES256-GCM-SHA384", false),
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 ("ECDHE-ECDSA-AES256-GCM-SHA384", false),
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 ("DHE-RSA-AES128-GCM-SHA256", false),
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ("ECDHE-RSA-AES128-GCM-SHA256", false),
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ("ECDHE-ECDSA-AES128-GCM-SHA256", false),
    TLS_RSA_WITH_AES_256_GCM_SHA384 ("AES256-GCM-SHA384", false);
	
	
    private final String opensslName;
    private final boolean tls13;

    CipherSuite(String opensslName, boolean tls13) {
        this.opensslName = opensslName;
        this.tls13 = tls13;
    }

    public String opensslName() { return opensslName; }
    public boolean isTls13()    { return tls13; }
}
