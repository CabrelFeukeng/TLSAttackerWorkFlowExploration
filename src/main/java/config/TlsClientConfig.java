package config;

import de.rub.nds.tlsattacker.core.config.Config;

public interface TlsClientConfig {

	public Config build();
	public String getHost();
	public int getPort();
	public String getTlsVersion();
}
