package org.springframework.security.saml.config;

import org.springframework.security.saml.saml2.metadata.NameId;

public class ExternalIdentityProviderConfiguration extends ExternalProviderConfiguration<ExternalIdentityProviderConfiguration> {

    private NameId nameId;
    private int assertionConsumerServiceIndex;

    public NameId getNameId() {
        return nameId;
    }

    public ExternalIdentityProviderConfiguration setNameId(NameId nameId) {
        this.nameId = nameId;
        return this;
    }

    public int getAssertionConsumerServiceIndex() {
        return assertionConsumerServiceIndex;
    }

    public ExternalIdentityProviderConfiguration setAssertionConsumerServiceIndex(int assertionConsumerServiceIndex) {
        this.assertionConsumerServiceIndex = assertionConsumerServiceIndex;
        return this;
    }
}
