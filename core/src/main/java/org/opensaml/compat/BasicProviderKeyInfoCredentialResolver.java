/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.opensaml.compat;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.KeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.impl.AbstractCriteriaFilteringCredentialResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoCriterion;
import org.opensaml.xmlsec.keyinfo.impl.KeyInfoProvider;
import org.opensaml.xmlsec.keyinfo.impl.KeyInfoResolutionContext;
import org.opensaml.xmlsec.keyinfo.impl.LocalKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.DEREncodedKeyValue;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.KeyName;
import org.opensaml.xmlsec.signature.KeyValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of {@link KeyInfoCredentialResolver} which resolves credentials based on a {@link KeyInfo} element
 * using a configured list of {@link KeyInfoProvider}'s and optional post-processing hooks.
 *
 * <p>
 * The majority of the processing of the KeyInfo and extraction of {@link Credential}'s from the KeyInfo is handled by
 * instances of {@link KeyInfoProvider}. An ordered list of KeyInfoProviders must be supplied to the resolver when it
 * is constructed.
 * </p>
 *
 * <p>
 * This resolver requires a {@link KeyInfoCriteria} to be supplied as the resolution criteria. It is permissible,
 * however, for the criteria's KeyInfo data object to be null. This allows for more convenient processing logic, for
 * example, in cases when a parent element allows an optional KeyInfo and when in fact a given instance does not contain
 * one. Specialized subclasses of this resolver may still attempt to return credentials in an implementation or
 * context-specific manner, as described below.
 * </p>
 *
 * <p>
 * Processing of the supplied KeyInfo element proceeds as follows:
 * <ol>
 * <li>A {@link KeyInfoResolutionContext} is instantiated. This resolution context is used to hold state shared amongst
 * all the providers and processing hooks which run within the resolver.</li>
 * <li>This resolution context is initialized and populated with the actual KeyInfo object being processed as well as
 * the values of any {@link KeyName} child elements present.</li>
 * <li>An attempt is then made to resolve a credential from any {@link KeyValue} child elements as described for
 * {@link #resolveKeyValue(KeyInfoResolutionContext, CriteriaSet, List)} If a credential is so resolved, its key will
 * also be placed in the resolution context</li>
 * <li>The remaining (non-KeyValue) children are then processed in document order. Each child element is processed by
 * the registered providers in provider list order. The credential or credentials resolved by the first provider to
 * successfully do so are added to the effective set of credentials returned by the resolver, and processing of that
 * child element terminates. Processing continues with the next child element.</li>
 * <li>At this point all KeyInfo children have been processed. If the effective set of credentials to return is empty,
 * and if a key was resolved from a KeyValue element and is available in the resolution context, a basic credential is
 * built with that key and is added to the effective set. Since the KeyInfo may have a plain KeyValue representation of
 * the key represented by the KeyInfo, in addition to a more specific key type/container (and hence credential)
 * representation, this technique avoids the unnecessary return of duplicate keys, returning only the more specific
 * credential representation of the key.</li>
 * <li>A post-processing hook is then called: {@link #postProcess(KeyInfoResolutionContext, CriteriaSet, List)}. The
 * default implementation is a no-op. This is an extension point by which subclasses may implement custom
 * post-processing of the effective credential set to be returned. One example use case is when the KeyInfo being
 * processed represents the public aspects (e.g. public key, or a key name or other identifier) of an encryption key
 * belonging to the resolving entity. The resolved public keys and other resolution context information may be used to
 * further resolve the credential or credentials containing the associated decryption key (i.e. a private or symmetric
 * key). For an example of such an implementation, see {@link LocalKeyInfoCredentialResolver}</li>
 * <li>Finally, if no credentials have been otherwise resolved, a final post-processing hook is called:
 * {@link #postProcessEmptyCredentials(KeyInfoResolutionContext, CriteriaSet, List)}. The default implementation is a
 * no-op. This is an extension point by which subclasses may implement custom logic to resolve credentials in an
 * implementation or context-specific manner, if no other mechanism has succeeded. Example usages might be to return a
 * default set of credentials, or to use non-KeyInfo-derived criteria or contextual information to determine the
 * credential or credentials to return.</li>
 * </ol>
 * </p>
 *
 */
public class BasicProviderKeyInfoCredentialResolver extends AbstractCriteriaFilteringCredentialResolver implements
    KeyInfoCredentialResolver {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(BasicProviderKeyInfoCredentialResolver.class);

    /** List of KeyInfo providers that are registered on this instance. */
    private List<KeyInfoProvider> providers;

    /**
     * Constructor.
     *
     * @param keyInfoProviders the list of KeyInfoProvider's to use in this resolver
     */
    public BasicProviderKeyInfoCredentialResolver(List<KeyInfoProvider> keyInfoProviders) {
        super();

        providers = new ArrayList<KeyInfoProvider>();
        providers.addAll(keyInfoProviders);
    }

    /**
     * Return the list of the KeyInfoProvider instances used in this resolver configuration.
     *
     * @return the list of providers configured for this resolver instance
     */
    protected List<KeyInfoProvider> getProviders() {
        return providers;
    }

    /** {@inheritDoc} */
    protected Iterable<Credential> resolveFromSource(CriteriaSet criteriaSet) throws ResolverException  {
        KeyInfoCriterion kiCriteria = criteriaSet.get(KeyInfoCriterion.class);
        if (kiCriteria == null) {
            log.error("No KeyInfo criteria supplied, resolver could not process");
            throw new ResolverException("Credential criteria set did not contain an instance of"
                                            + "KeyInfoCredentialCriteria");
        }
        KeyInfo keyInfo = kiCriteria.getKeyInfo();

        // This will be the list of credentials to return.
        List<Credential> credentials = new ArrayList<Credential>();

        KeyInfoResolutionContext kiContext = new KeyInfoResolutionContext(credentials);

        // Note: we allow KeyInfo to be null to handle case where application context,
        // other accompanying criteria, etc, should be used to resolve credentials via hooks below.
        if (keyInfo != null) {
            processKeyInfo(keyInfo, kiContext, criteriaSet, credentials);
        } else {
            log.info("KeyInfo was null, any credentials will be resolved by post-processing hooks only");
        }

        // Postprocessing hook
        postProcess(kiContext, criteriaSet, credentials);

        // Final empty credential hook
        if (credentials.isEmpty()) {
            log.debug("No credentials were found, calling empty credentials post-processing hook");
            postProcessEmptyCredentials(kiContext, criteriaSet, credentials);
        }

        log.debug("A total of {} credentials were resolved", credentials.size());
        return credentials;
    }

    /**
     * The main processing logic implemented by this resolver.
     *
     * @param keyInfo the KeyInfo being processed
     * @param kiContext KeyInfo resolution context
     * @param criteriaSet the credential criteria used to resolve credentials
     * @param credentials the list which will store the resolved credentials
     * @throws SecurityException thrown if there is an error during processing
     */
    private void processKeyInfo(KeyInfo keyInfo, KeyInfoResolutionContext kiContext, CriteriaSet criteriaSet,
                                List<Credential> credentials) throws ResolverException  {

        // Initialize the resolution context that will be used by the provider plugins.
        // This processes the KeyName and the KeyValue children, if either are present.
        initResolutionContext(kiContext, keyInfo, criteriaSet);

        // Store these off so we later use the original values,
        // unmodified by other providers which later run.
        Key keyValueKey = kiContext.getKey();
        HashSet<String> keyNames = new HashSet<String>();
        keyNames.addAll(kiContext.getKeyNames());

        // Now process all (non-KeyValue) children
        processKeyInfoChildren(kiContext, criteriaSet, credentials);

        if (credentials.isEmpty() && keyValueKey != null) {
            // Add the credential based on plain KeyValue if no more specifc cred type was found
            Credential keyValueCredential = buildBasicCredential(keyValueKey, keyNames);
            if (keyValueCredential != null) {
                log.debug("No credentials were extracted by registered non-KeyValue handling providers, "
                              + "adding KeyValue credential to returned credential set");
                credentials.add(keyValueCredential);
            }
        }
    }

    /**
     * Hook for subclasses to do post-processing of the credential set after all KeyInfo children have been processed.
     *
     * For example, the previously resolved credentials might be used to index into a store of local credentials, where
     * the index is a key name or the public half of a key pair extracted from the KeyInfo.
     *
     * @param kiContext KeyInfo resolution context
     * @param criteriaSet the credential criteria used to resolve credentials
     * @param credentials the list which will store the resolved credentials
     * @throws SecurityException thrown if there is an error during processing
     */
    protected void postProcess(KeyInfoResolutionContext kiContext, CriteriaSet criteriaSet,
                               List<Credential> credentials) throws ResolverException {

    }

    /**
     * Hook for processing the case where no credentials were returned by any resolution method by any provider, nor by
     * the processing of the {@link #postProcess(KeyInfoResolutionContext, CriteriaSet, List)} hook.
     *
     * @param kiContext KeyInfo resolution context
     * @param criteriaSet the credential criteria used to resolve credentials
     * @param credentials the list which will store the resolved credentials
     *
     * @throws SecurityException thrown if there is an error during processing
     */
    protected void postProcessEmptyCredentials(KeyInfoResolutionContext kiContext, CriteriaSet criteriaSet,
                                               List<Credential> credentials) throws ResolverException {

    }

    /**
     * Use registered providers to process the non-KeyValue/DEREncodedKeyValue children of KeyInfo.
     *
     * Each child element is processed in document order. Each child element is processed by each provider in the
     * ordered list of providers. The credential or credentials resolved by the first provider to successfully do so are
     * added to the effective set resolved by the KeyInfo resolver.
     *
     * @param kiContext KeyInfo resolution context
     * @param criteriaSet the credential criteria used to resolve credentials
     * @param credentials the list which will store the resolved credentials
     * @throws SecurityException thrown if there is a provider error processing the KeyInfo children
     */
    protected void processKeyInfoChildren(KeyInfoResolutionContext kiContext, CriteriaSet criteriaSet,
                                          List<Credential> credentials) throws ResolverException {

        for (XMLObject keyInfoChild : kiContext.getKeyInfo().getXMLObjects()) {

            if (keyInfoChild instanceof KeyValue || keyInfoChild instanceof DEREncodedKeyValue) {
                continue;
            }

            log.debug("Processing KeyInfo child with qname: {}", keyInfoChild.getElementQName());
            Collection<Credential> childCreds = processKeyInfoChild(kiContext, criteriaSet, keyInfoChild);

            if (childCreds != null && !childCreds.isEmpty()) {
                credentials.addAll(childCreds);
            } else {
                // Not really an error or warning if KeyName doesn't produce a credential
                if (keyInfoChild instanceof KeyName) {
                    log.debug("KeyName, with value {}, did not independently produce a credential based on any registered providers",
                              ((KeyName) keyInfoChild).getValue());

                } else {
                    log.warn("No credentials could be extracted from KeyInfo child with qname {} by any registered provider",
                             keyInfoChild.getElementQName());
                }
            }
        }
    }

    /**
     * Process the given KeyInfo child with the registered providers.
     *
     * The child element is processed by each provider in the ordered list of providers. The credential or credentials
     * resolved by the first provider to successfully do so are returned and processing of the child element is
     * terminated.
     *
     * @param kiContext KeyInfo resolution context
     * @param criteriaSet the credential criteria used to resolve credentials
     * @param keyInfoChild the KeyInfo to evaluate
     * @return the collection of resolved credentials, or null
     * @throws SecurityException thrown if there is a provider error processing the KeyInfo child
     */
    protected Collection<Credential> processKeyInfoChild(KeyInfoResolutionContext kiContext, CriteriaSet criteriaSet,
                                                         XMLObject keyInfoChild) throws ResolverException   {

        for (KeyInfoProvider provider : getProviders()) {

            if (!provider.handles(keyInfoChild)) {
                log.debug("Provider {} doesn't handle objects of type {}, skipping", provider.getClass().getName(),
                          keyInfoChild.getElementQName());
                continue;
            }

            log.debug("Processing KeyInfo child {} with provider {}", keyInfoChild.getElementQName(), provider
                .getClass().getName());
            try {
                Collection<Credential> creds = provider.process(this, keyInfoChild, criteriaSet, kiContext);

                if (creds != null && !creds.isEmpty()) {
                    log.debug("Credentials successfully extracted from child {} by provider {}", keyInfoChild
                        .getElementQName(), provider.getClass().getName());
                    return creds;
                }
            } catch (SecurityException e) {
                throw new ResolverException(e);
            }
        }
        return null;
    }

    /**
     * Initialize the resolution context that will be used by the providers.
     *
     * The supplied KeyInfo object is stored in the context, as well as the values of any {@link KeyName} children
     * present. Finally if a credential is resolveble by any registered provider from a plain {@link KeyValue} child,
     * the key from that credential is also stored in the context.
     *
     * @param kiContext KeyInfo resolution context
     * @param keyInfo the KeyInfo to evaluate
     * @param criteriaSet the credential criteria used to resolve credentials
     * @throws SecurityException thrown if there is an error processing the KeyValue children
     */
    protected void initResolutionContext(KeyInfoResolutionContext kiContext, KeyInfo keyInfo, CriteriaSet criteriaSet)
        throws ResolverException  {

        kiContext.setKeyInfo(keyInfo);

        // Extract all KeyNames
        kiContext.getKeyNames().addAll(KeyInfoHelper.getKeyNames(keyInfo));
        log.debug("Found {} key names: {}", kiContext.getKeyNames().size(), kiContext.getKeyNames());

        // Extract the Credential based on the (singular) key from an existing KeyValue(s).
        resolveKeyValue(kiContext, criteriaSet, keyInfo.getKeyValues());

        // Extract the Credential based on the (singular) key from an existing DEREncodedKeyValue(s).
        resolveKeyValue(kiContext, criteriaSet, keyInfo.getXMLObjects(DEREncodedKeyValue.DEFAULT_ELEMENT_NAME));
    }

    /**
     * Resolve the key from any KeyValue or DEREncodedKeyValue element that may be present, and store the resulting
     * key in the resolution context.
     *
     * Each element is processed in turn in document order. Each element will be processed by each provider in
     * the ordered list of registered providers. The key from the first credential successfully resolved
     * will be stored in the resolution context.
     *
     * Note: This resolver implementation assumes that KeyInfo will not be abused via-a-vis the Signature
     * specificiation, and that therefore all elements (if there are even more than one) will all resolve to the
     * same key value. The KeyInfo might, for example have multiple KeyValue children, containing different
     * representations of the same key. Therefore, only the first credential derived will be be utilized.
     *
     * @param kiContext KeyInfo resolution context
     * @param criteriaSet the credential criteria used to resolve credentials
     * @param keyValues the KeyValue or DEREncodedKeyValue children to evaluate
     * @throws SecurityException thrown if there is an error resolving the key from the KeyValue
     */
    protected void resolveKeyValue(KeyInfoResolutionContext kiContext, CriteriaSet criteriaSet,
                                   List<? extends XMLObject> keyValues) throws ResolverException  {

        for (XMLObject keyValue : keyValues) {
            if (!(keyValue instanceof KeyValue) && !(keyValue instanceof DEREncodedKeyValue)) {
                continue;
            }
            Collection<Credential> creds = processKeyInfoChild(kiContext, criteriaSet, keyValue);
            if (creds != null) {
                for (Credential cred : creds) {
                    Key key = extractKeyValue(cred);
                    if (key != null) {
                        kiContext.setKey(key);
                        log.debug("Found a credential based on a KeyValue/DEREncodedKeyValue having key type: {}",
                                  key.getAlgorithm());
                        return;
                    }
                }
            }
        }
    }

    /**
     * Construct a basic credential containing the specified key and set of key names.
     *
     * @param key the key to include in the credential
     * @param keyNames the key names to include in the credential
     * @return a basic credential with the specified key and key names
     * @throws SecurityException if there is an error building the credential
     */
    protected Credential buildBasicCredential(Key key, Set<String> keyNames) throws ResolverException {
        if (key == null) {
            log.debug("Key supplied was null, could not build credential");
            return null;
        }

        BasicCredential basicCred = new BasicCredential() {};

        basicCred.getKeyNames().addAll(keyNames);

        if (key instanceof PublicKey) {
            basicCred.setPublicKey((PublicKey) key);
        } else if (key instanceof SecretKey) {
            basicCred.setSecretKey((SecretKey) key);
        } else if (key instanceof PrivateKey) {
            // This would be unusual for most KeyInfo use cases,
            // but go ahead and try and handle it
            PrivateKey privateKey = (PrivateKey) key;
            try {
                PublicKey publicKey = SecurityHelper.derivePublicKey(privateKey);
                if (publicKey != null) {
                    basicCred.setPublicKey(publicKey);
                    basicCred.setPrivateKey(privateKey);
                } else {
                    log.error("Failed to derive public key from private key");
                    return null;
                }
            } catch (KeyException e) {
                log.error("Could not derive public key from private key", e);
                return null;
            }
        } else {
            log.error(String.format("Key was of an unsupported type '%s'", key.getClass().getName()));
            return null;
        }

        return basicCred;
    }

    /**
     * Utility method to extract any key that might be present in the specified Credential.
     *
     * @param cred the Credential to evaluate
     * @return the Key contained in the credential, or null if it does not contain a key.
     */
    protected Key extractKeyValue(Credential cred) {
        if (cred == null) {
            return null;
        }
        if (cred.getPublicKey() != null) {
            return cred.getPublicKey();
        }
        // This could happen if key is derived, e.g. key agreement, etc
        if (cred.getSecretKey() != null) {
            return cred.getSecretKey();
        }
        // Perhaps unlikely, but go ahead and check
        if (cred.getPrivateKey() != null) {
            return cred.getPrivateKey();
        }
        return null;
    }

}
