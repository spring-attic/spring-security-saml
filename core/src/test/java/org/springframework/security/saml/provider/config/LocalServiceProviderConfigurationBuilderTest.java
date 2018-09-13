package org.springframework.security.saml.provider.config;

import org.hamcrest.Matchers;
import org.hamcrest.core.Is;
import org.junit.jupiter.api.Test;
import org.springframework.security.saml.provider.service.config.ExternalIdentityProviderConfiguration;
import org.springframework.security.saml.provider.service.config.LocalServiceProviderConfiguration;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

public class LocalServiceProviderConfigurationBuilderTest {

    @Test
    public void emptyObjectCreatedByBuilderIsSameAsNewInstance(){
        LocalServiceProviderConfiguration instance = new LocalServiceProviderConfiguration.Builder().build();

        assertThat(instance, Matchers.samePropertyValuesAs(new LocalServiceProviderConfiguration()));
    }

    @Test
    public void canSetAllThePropertiesOfConfigurationInstanceWithBuilder(){
        RotatingKeys keys = new RotatingKeys();
        List<NameId> nameids = Arrays.asList(NameId.TRANSIENT);
        List<ExternalIdentityProviderConfiguration> providers = new LinkedList<>();
        LocalServiceProviderConfiguration instance = new LocalServiceProviderConfiguration.Builder()
                .setSignRequests(true)
                .setWantAssertionsSigned(true)
                .setAlias("aalliiaass")
                .setBasePath("base---path")
                .setDefaultDigest(DigestMethod.RIPEMD160)
                .setDefaultSigningAlgorithm(AlgorithmMethod.RSA_RIPEMD160)
                .setEntityId("e-n-t-i-t-y-I-d")
                .setKeys(keys)
                .setMetadata("meta!data!")
                .setNameIds(nameids)
                .setPrefix("ppf/")
                .setProviders(providers)
                .setSignMetadata(true)
                .setSingleLogoutEnabled(true)
                .build();

        assertThat(instance.isSignRequests(), is(true));
        assertThat(instance.isWantAssertionsSigned(), is(true));
        assertThat(instance.getAlias(), is("aalliiaass"));
        assertThat(instance.getBasePath(), is("base---path"));
        assertThat(instance.getDefaultDigest(), is(DigestMethod.RIPEMD160));
        assertThat(instance.getDefaultSigningAlgorithm(), is(AlgorithmMethod.RSA_RIPEMD160));
        assertThat(instance.getEntityId(), is("e-n-t-i-t-y-I-d"));
        assertThat(instance.getKeys(), is(keys));
        assertThat(instance.getMetadata(), is("meta!data!"));
        assertThat(instance.getNameIds(), is(nameids));
        assertThat(instance.getPrefix(), is("ppf/"));
        assertThat(instance.getProviders(), is(providers));
        assertThat(instance.isSignMetadata(), is(true));
        assertThat(instance.isSingleLogoutEnabled(), is(true));
    }
}
