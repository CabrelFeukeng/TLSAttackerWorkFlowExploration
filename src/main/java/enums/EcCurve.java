package enums;

public enum EcCurve {
    X25519      ("X25519"),
    PRIME256V1  ("prime256v1"),
    SECP384R1   ("secp384r1"),
    SECP521R1   ("secp521r1");

    private final String name;
    EcCurve(String name) { this.name = name; }
    public String curveName() { return name; }
}