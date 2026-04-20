package config;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;

public interface TlsClientConfig {

	public Config build();
	public String getHost();
	public int getPort();
	public String getTlsVersion();
	public void setCipherSuites(CipherSuite[] cipherSuites);
}
