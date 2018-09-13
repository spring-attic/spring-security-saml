package org.springframework.security.saml.provider.config;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.security.saml.provider.config.RotatingKeys;
import org.springframework.security.saml.provider.identity.config.ExternalServiceProviderConfiguration;
import org.springframework.security.saml.provider.identity.config.LocalIdentityProviderConfiguration;
import org.springframework.security.saml.saml2.encrypt.DataEncryptionMethod;
import org.springframework.security.saml.saml2.encrypt.KeyEncryptionMethod;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

public class LocalIdentityProviderConfigurationBuilderTest {

    @Test
    public void createsEmptyObject(){
        LocalIdentityProviderConfiguration instance = new LocalIdentityProviderConfiguration.Builder().build();

        assertThat(instance, Matchers.samePropertyValuesAs(new LocalIdentityProviderConfiguration()));
    }


    @Test
    public void configuresBuilderAndBuildsObjectWithConfiguredProperties(){
        RotatingKeys keys = new RotatingKeys();
        List<ExternalServiceProviderConfiguration> providers = new ArrayList<>();
        LocalIdentityProviderConfiguration instance = new LocalIdentityProviderConfiguration.Builder()
                .setEncryptAssertions(true)
                .setKeyEncryptionAlgorithm(KeyEncryptionMethod.RSA_OAEP_MGF1P)
                .setSignAssertions(true)
                .setWantRequestsSigned(true)
                .setDataEncryptionAlgorithm(DataEncryptionMethod.AES192_CBC)
                .setNotBefore(1234L)
                .setNotOnOrAfter(5678L)
                .setSessionNotOnOrAfter(9999L)
                .setAlias("xxx saml xxx")
                .setBasePath("/aaa/aa")
                .setDefaultDigest(DigestMethod.SHA512)
                .setDefaultSigningAlgorithm(AlgorithmMethod.RSA_SHA512)
                .setEntityId("xxx entityId xxx")
                .setKeys(keys)
                .setMetadata("xxx metadata xxx")
                .setNameIds(Arrays.asList(NameId.EMAIL, NameId.PERSISTENT))
                .setPrefix("prefix/")
                .setProviders(providers)
                .setSignMetadata(true)
                .setSingleLogoutEnabled(true)
                .build();

        assertThat(instance.isEncryptAssertions(), is(true));
        assertThat(instance.getKeyEncryptionAlgorithm(), is(KeyEncryptionMethod.RSA_OAEP_MGF1P));
        assertThat(instance.isSignAssertions(), is(true));
        assertThat(instance.isWantRequestsSigned(), is(true));
        assertThat(instance.getDataEncryptionAlgorithm(), is(DataEncryptionMethod.AES192_CBC));
        assertThat(instance.getNotBefore(), is(1234L));
        assertThat(instance.getNotOnOrAfter(), is(5678L));
        assertThat(instance.getSessionNotOnOrAfter(), is(9999L));
        assertThat(instance.getAlias(), is("xxx saml xxx"));
        assertThat(instance.getBasePath(), is("/aaa/aa"));
        assertThat(instance.getDefaultDigest(), is(DigestMethod.SHA512));
        assertThat(instance.getDefaultSigningAlgorithm(), is(AlgorithmMethod.RSA_SHA512));
        assertThat(instance.getEntityId(), is("xxx entityId xxx"));
        assertThat(instance.getKeys(), is(keys));
        assertThat(instance.getMetadata(), is("xxx metadata xxx"));
        assertThat(instance.getNameIds(), is(Arrays.asList(NameId.EMAIL, NameId.PERSISTENT)));
        assertThat(instance.getPrefix(), is("prefix/"));
        assertThat(instance.getProviders(), is(providers));
        assertThat(instance.isSignMetadata(), is(true));
        assertThat(instance.isSingleLogoutEnabled(), is(true));
    }

    @Test
    public void removesSlashAtStartOfPrefix(){
        LocalIdentityProviderConfiguration instance =  new LocalIdentityProviderConfiguration.Builder()
                .setPrefix("/test/")
                .build();

        assertThat(instance.getPrefix(), is("test/"));
    }

    @Test
    public void addsSlashAtTheEndOfPrefixIfMissing(){
        LocalIdentityProviderConfiguration instance =  new LocalIdentityProviderConfiguration.Builder()
                .setPrefix("test")
                .build();

        assertThat(instance.getPrefix(), is("test/"));
    }
}
