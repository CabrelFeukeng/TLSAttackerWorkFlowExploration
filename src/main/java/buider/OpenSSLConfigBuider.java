package buider;

import java.util.List;

import config.OpenSSLServerConfig;
import enums.CipherSuite;
import enums.EcCurve;
import enums.TlsVersion;

public interface OpenSSLConfigBuider {
	
	public OpenSSLConfigBuider host(String host);
    public OpenSSLConfigBuider port(int port);
    public OpenSSLConfigBuider certFile(String certFile);
    public OpenSSLConfigBuider keyFile(String keyFile);
    public OpenSSLConfigBuider version(TlsVersion v);
    public OpenSSLConfigBuider ecCurve(EcCurve curve);
    public OpenSSLConfigBuider verbose(boolean v);
    public OpenSSLConfigBuider extraArgs(String args);
    public OpenSSLConfigBuider cipherSuite(CipherSuite cs);
    public OpenSSLConfigBuider cipherSuites(List<CipherSuite> list);
    public OpenSSLServerConfig build();

}
