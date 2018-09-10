package org.springframework.security.saml.provider.config;

import java.time.Clock;

import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.provider.SamlServerConfiguration;

public class ThreadLocalSamlConfigurationRepository implements SamlConfigurationRepository {

	private static InheritableThreadLocal<ExpiringEntry> threadLocal = new InheritableThreadLocal<>();

	private final SamlConfigurationRepository initialValueProvider;
	private final Clock clock;
	private long expirationMillis = 10 * 1000;

	public ThreadLocalSamlConfigurationRepository(SamlConfigurationRepository initialValueProvider) {
		this(initialValueProvider, Clock.systemUTC());
	}

	public ThreadLocalSamlConfigurationRepository(SamlConfigurationRepository initialValueProvider, Clock clock) {
		this.initialValueProvider = initialValueProvider;
		this.clock = clock;
	}

	@Override
	public SamlServerConfiguration getServerConfiguration() {
		ExpiringEntry expiringEntry = threadLocal.get();
		SamlServerConfiguration result = null;
		if (expiringEntry != null) {
			result = expiringEntry.getConfiguration(getExpirationMillis());
			if (result == null) {
				reset();
			}
		}
		if (result == null) {
			try {
				result = initialValueProvider.getServerConfiguration().clone();
			} catch (CloneNotSupportedException e) {
				throw new SamlException(e);
			}
		}
		return result;
	}

	protected void setServerConfiguration(SamlServerConfiguration configuration) {
		if (configuration == null) {
			reset();
		}
		else {
			threadLocal.set(
				new ExpiringEntry(clock, configuration)
			);
		}
	}

	public void reset() {
		threadLocal.remove();
	}

	public long getExpirationMillis() {
		return expirationMillis;
	}

	public ThreadLocalSamlConfigurationRepository setExpirationMillis(long expirationMillis) {
		this.expirationMillis = expirationMillis;
		return this;
	}

	private static class ExpiringEntry {
		private Clock clock;
		private long created;
		private SamlServerConfiguration configuration;

		public ExpiringEntry(Clock clock, SamlServerConfiguration configuration) {
			this.clock = clock;
			setConfiguration(configuration);
		}

		public long getCreated() {
			return created;
		}

		public void setConfiguration(SamlServerConfiguration configuration) {
			this.configuration = configuration;
			created = configuration==null ? 0 : clock.millis();
		}

		public SamlServerConfiguration getConfiguration(long expiration) {
			if ((created+expiration) > clock.millis()) {
				return configuration;
			}
			else {
				return null;
			}
		}
	}
}
