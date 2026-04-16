package config;

import java.util.ArrayList;
import java.util.List;

import buider.OpenSSLConfigBuider;
import buider.OpenSSLConfigBuiderImp;
import enums.CipherSuiteC;
import enums.EcCurve;
import enums.TlsVersion;

/**
 *
 */
public final class OpenSSLServerConfig {

    private final String       host;
    private final int          port;
    private final String       certFile;
    private final String       keyFile;
    private final TlsVersion   tlsVersion;
    private final List<CipherSuiteC> cipherSuites;
    private final EcCurve      ecCurve;
    private final boolean      verbose;       // -msg -state
    private final boolean wwwArg;

    public OpenSSLServerConfig(OpenSSLConfigBuiderImp b) {
        this.host          = b.host();
        this.port          = b.port();
        this.certFile      = b.certFile();
        this.keyFile       = b.keyFile();
        this.tlsVersion    = b.tlsVersion();
        this.cipherSuites  = List.copyOf(b.cipherSuites());
        this.ecCurve       = b.ecCurve();
        this.verbose       = b.verbose();
        this.wwwArg        = b.wwwArg();
        
    }

    public static OpenSSLConfigBuider builder() { return new OpenSSLConfigBuiderImp(); }


    public static OpenSSLServerConfig defaultTls12() {
        return builder()
            .version(TlsVersion.TLS_1_2)
            .wwwArg(true)
            .cipherSuite(CipherSuiteC.TLS_RSA_WITH_AES_128_GCM_SHA256)
            .cipherSuite(CipherSuiteC.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384)
            .build();
    }

    public static OpenSSLServerConfig defaultTls13() {
        return builder()
            .version(TlsVersion.TLS_1_3)
            .cipherSuite(CipherSuiteC.TLS_AES_256_GCM_SHA384)
            .cipherSuite(CipherSuiteC.TLS_AES_128_GCM_SHA256)
            .ecCurve(EcCurve.X25519)
            .wwwArg(true)
            .build();
    }

    public List<String> toCommand() {
        List<String> cmd = new ArrayList<>();
        cmd.add("openssl");
        cmd.add("s_server");

        cmd.add("-accept"); cmd.add(String.valueOf(port));
        cmd.add("-cert");   cmd.add(certFile);
        cmd.add("-key");    cmd.add(keyFile);
        
        

        if (tlsVersion != null) {
            cmd.add(tlsVersion.flag());
        } else {
            cmd.add("-tls1_3"); // Par défaut
        }
        
        if (!cipherSuites.isEmpty()) {
            List<String> tls12 = cipherSuites.stream()
                .filter(c -> !c.isTls13())
                .map(CipherSuiteC::opensslName)
                .toList();
            List<String> tls13 = cipherSuites.stream()
                .filter(CipherSuiteC::isTls13)
                .map(CipherSuiteC::opensslName)
                .toList();

            if (!tls12.isEmpty()) {
                cmd.add("-cipher");
                cmd.add(String.join(":", tls12));
            }
            if (!tls13.isEmpty()) {
                cmd.add("-ciphersuites");
                cmd.add(String.join(":", tls13));
            }
        }

        if (ecCurve != null) {
            boolean isTls13Mode = tlsVersion == TlsVersion.TLS_1_3;
            if (isTls13Mode) {
                cmd.add("-groups");
                cmd.add(ecCurve.curveName());
            } else {
                cmd.add("-named_curve");
                cmd.add(ecCurve.curveName());
            }
        }
        
        if(wwwArg) {
        	cmd.add("-www");
        }
        
        return List.copyOf(cmd);
    }


    public String       host()         { return host; }
    public int          port()         { return port; }
    public String       certFile()     { return certFile; }
    public String       keyFile()      { return keyFile; }
    public TlsVersion   tlsVersion()   { return tlsVersion; }
    public List<CipherSuiteC> cipherSuites() { return cipherSuites; }
    public EcCurve      ecCurve()      { return ecCurve; }
    public boolean      verbose()      { return verbose; }

    @Override
    public String toString() {
        return String.join(" ", toCommand());
    }
}