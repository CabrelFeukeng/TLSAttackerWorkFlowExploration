package enums;

public enum TlsVersion {
    TLS_1_0("-tls1"),
    TLS_1_1("-tls1_1"),
    TLS_1_2("-tls1_2"),
    TLS_1_3("-tls1_3");

    private final String flag;
    TlsVersion(String flag) { this.flag = flag; }
    public String flag()    { return flag; }
}
