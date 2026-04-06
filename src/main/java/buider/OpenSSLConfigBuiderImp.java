package buider;

import java.util.ArrayList;
import java.util.List;

import config.OpenSSLServerConfig;
import enums.CipherSuite;
import enums.EcCurve;
import enums.TlsVersion;

public class OpenSSLConfigBuiderImp implements OpenSSLConfigBuider{
	
	private String       host         = "localhost";
    private int          port         = 1234;
    private String       certFile     = "src/main/resources/data/server.crt";
    private String       keyFile      = "src/main/resources/data/server.key";
    private TlsVersion   tlsVersion   = TlsVersion.TLS_1_2;
    private List<CipherSuite> cipherSuites = new ArrayList<>();
    private EcCurve      ecCurve      = null;
    private boolean      verbose      = false;
    private String       extraArgs    = null;

    public OpenSSLConfigBuiderImp() {}

    public OpenSSLConfigBuider host(String host)             { this.host = host;               return this; }
    public OpenSSLConfigBuider port(int port)                { this.port = port;               return this; }
    public OpenSSLConfigBuider certFile(String certFile)     { this.certFile = certFile;       return this; }
    public OpenSSLConfigBuider keyFile(String keyFile)       { this.keyFile = keyFile;         return this; }
    public OpenSSLConfigBuider version(TlsVersion v)         { this.tlsVersion = v;           return this; }
    public OpenSSLConfigBuider ecCurve(EcCurve curve)        { this.ecCurve = curve;           return this; }
    public OpenSSLConfigBuider verbose(boolean v)            { this.verbose = v;               return this; }
    public OpenSSLConfigBuider extraArgs(String args)        { this.extraArgs = args;          return this; }

    public OpenSSLConfigBuider cipherSuite(CipherSuite cs) {
        this.cipherSuites.add(cs);
        return this;
    }

    public OpenSSLConfigBuider cipherSuites(List<CipherSuite> list) {
        this.cipherSuites.addAll(list);
        return this;
    }

    public OpenSSLServerConfig build() {
        if (certFile == null || keyFile == null)
            throw new IllegalStateException("certFile and keyFile are required");
        return new OpenSSLServerConfig(this);
    }
    
    public String       host()         { return host; }
    public String       extraArgs()         { return extraArgs; }
    public int          port()         { return port; }
    public String       certFile()     { return certFile; }
    public String       keyFile()      { return keyFile; }
    public TlsVersion   tlsVersion()   { return tlsVersion; }
    public List<CipherSuite> cipherSuites() { return cipherSuites; }
    public EcCurve      ecCurve()      { return ecCurve; }
    public boolean      verbose()      { return verbose; }
    
    

}
