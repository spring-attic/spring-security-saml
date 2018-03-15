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


import javax.annotation.Nonnull;
import javax.xml.namespace.QName;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import net.shibboleth.utilities.java.support.collection.LazySet;
import net.shibboleth.utilities.java.support.collection.LockableClassToInstanceMultiMap;
import org.joda.time.DateTime;
import org.opensaml.core.xml.Namespace;
import org.opensaml.core.xml.NamespaceManager;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSBooleanValue;
import org.opensaml.core.xml.util.IDIndex;
import org.opensaml.saml.metadata.resolver.filter.MetadataFilter;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.xmlsec.signature.Signature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

/**
 * A metadata provider that uses registered providers, in turn, to answer queries.
 *
 * When searching for entity specific information (entity metadata, roles, etc.) the entity descriptor used is the first
 * non-null descriptor found while iterating over the registered providers in insertion order.
 *
 * This chaining provider implements observation by registering an observer with each contained provider. When the
 * contained provider emits a change this provider will also emit a change to observers registered with it. As such,
 * developers should be careful not to register a the same observer with both container providers and this provider.
 * Doing so will result in an observer being notified twice for each change.
 */
public class ChainingMetadataProvider extends BaseMetadataProvider implements ObservableMetadataProvider {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(ChainingMetadataProvider.class);

    /** List of registered observers. */
    private List<Observer> observers;

    /** Registered providers. */
    private List<MetadataProvider> providers;

    /** Lock used to block reads during write and vice versa. */
    private ReadWriteLock providerLock;

    /** Constructor. */
    public ChainingMetadataProvider() {
        super();
        observers = new CopyOnWriteArrayList<Observer>();
        providers = Collections.EMPTY_LIST;
        providerLock = new ReentrantReadWriteLock(true);
    }

    /**
     * Gets an immutable the list of currently registered providers.
     *
     * @return list of currently registered providers
     */
    public List<MetadataProvider> getProviders() {
        return providers;
    }

    /**
     * Replaces the current set of metadata providers with give collection.
     *
     * @param newProviders the metadata providers to replace the current providers with
     *
     * @throws MetadataProviderException thrown if there is a problem adding the metadata provider
     */
    public void setProviders(List<MetadataProvider> newProviders) throws MetadataProviderException {
        Lock writeLock = providerLock.writeLock();
        writeLock.lock();

        try {
            if (newProviders == null || newProviders.isEmpty()) {
                providers = Collections.emptyList();
                return;
            }

            ArrayList<MetadataProvider> checkedProviders = new ArrayList<MetadataProvider>();
            for (MetadataProvider provider : newProviders) {
                doAddMetadataProvider(provider, checkedProviders);
            }
            providers = Collections.unmodifiableList(checkedProviders);
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Adds a metadata provider to the list of registered providers.
     *
     * @param newProvider the provider to be added
     *
     * @throws MetadataProviderException thrown if there is a problem adding the metadata provider
     */
    public void addMetadataProvider(MetadataProvider newProvider) throws MetadataProviderException {
        Lock writeLock = providerLock.writeLock();
        writeLock.lock();

        try {
            ArrayList<MetadataProvider> checkedProviders = new ArrayList<MetadataProvider>(providers);
            doAddMetadataProvider(newProvider, checkedProviders);
            providers = Collections.unmodifiableList(checkedProviders);
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Adds a metadata provider to the given collection. The new provider is checked to see if it is null, if not the
     * providers {@link MetadataProvider#requireValidMetadata()} property is set to the value of this metadata
     * provider's property. If the given metadata provider is an instance of {@link ObservableMetadataProvider} then a
     * ContainedProviderObserver is added to it as well.
     *
     * @param provider provider to be added to the collection
     * @param providerList collection to which the provider is added
     */
    protected void doAddMetadataProvider(MetadataProvider provider, List<MetadataProvider> providerList) {
        if (provider != null) {
            provider.setRequireValidMetadata(requireValidMetadata());

            if (provider instanceof ObservableMetadataProvider) {
                ((ObservableMetadataProvider) provider).getObservers().add(new ContainedProviderObserver());
            }

            providerList.add(provider);
        }
    }

    /**
     * Removes a metadata provider from the list of registered providers.
     *
     * @param provider provider to be removed
     */
    public void removeMetadataProvider(MetadataProvider provider) {
        Lock writeLock = providerLock.writeLock();
        writeLock.lock();

        ObservableMetadataProvider observableProvider;
        try {
            if (providers.remove(provider) && provider instanceof ObservableMetadataProvider) {
                observableProvider = (ObservableMetadataProvider) provider;
                for (Observer observer : observableProvider.getObservers()) {
                    if (observer instanceof ContainedProviderObserver) {
                        observableProvider.getObservers().remove(observer);
                    }
                }
            }
        } finally {
            writeLock.unlock();
        }
    }

    /** {@inheritDoc} */
    public void setRequireValidMetadata(boolean requireValidMetadata) {
        super.setRequireValidMetadata(requireValidMetadata);

        Lock writeLock = providerLock.writeLock();
        writeLock.lock();
        try {
            for (MetadataProvider provider : providers) {
                provider.setRequireValidMetadata(requireValidMetadata);
            }
        } finally {
            writeLock.unlock();
        }
    }

    /** {@inheritDoc} */
    public MetadataFilter getMetadataFilter() {
        log.warn("Attempt to access unsupported MetadataFilter property on ChainingMetadataProvider");
        return null;
    }

    /** {@inheritDoc} */
    public void setMetadataFilter(MetadataFilter newFilter) throws MetadataProviderException {
        throw new UnsupportedOperationException("Metadata filters are not supported on ChainingMetadataProviders");
    }

    /**
     * Gets the metadata from every registered provider and places each within a newly created EntitiesDescriptor.
     *
     * {@inheritDoc}
     */
    public XMLObject getMetadata() throws MetadataProviderException {
        return new ChainingEntitiesDescriptor();
    }

    /** {@inheritDoc} */
    public EntitiesDescriptor getEntitiesDescriptor(String name) throws MetadataProviderException {
        Lock readLock = providerLock.readLock();
        readLock.lock();

        EntitiesDescriptor descriptor = null;
        try {
            for (MetadataProvider provider : providers) {
                log.debug("Checking child metadata provider for entities descriptor with name: {}", name);
                try {
                    descriptor = provider.getEntitiesDescriptor(name);
                    if (descriptor != null) {
                        break;
                    }
                } catch (MetadataProviderException e) {
                    log.warn("Error retrieving metadata from provider of type {}, proceeding to next provider",
                             provider.getClass().getName(), e);
                    continue;
                }
            }
        } finally {
            readLock.unlock();
        }

        return descriptor;
    }

    /** {@inheritDoc} */
    public EntityDescriptor getEntityDescriptor(String entityID) throws MetadataProviderException {
        Lock readLock = providerLock.readLock();
        readLock.lock();

        EntityDescriptor descriptor = null;
        try {
            for (MetadataProvider provider : providers) {
                log.debug("Checking child metadata provider for entity descriptor with entity ID: {}", entityID);
                try {
                    descriptor = provider.getEntityDescriptor(entityID);
                    if (descriptor != null) {
                        break;
                    }
                } catch (MetadataProviderException e) {
                    log.warn("Error retrieving metadata from provider of type {}, proceeding to next provider",
                             provider.getClass().getName(), e);
                    continue;
                }
            }
        } finally {
            readLock.unlock();
        }

        return descriptor;
    }

    /** {@inheritDoc} */
    public List<RoleDescriptor> getRole(String entityID, QName roleName) throws MetadataProviderException {
        Lock readLock = providerLock.readLock();
        readLock.lock();

        List<RoleDescriptor> roleDescriptors = null;
        try {
            for (MetadataProvider provider : providers) {
                log.debug("Checking child metadata provider for entity descriptor with entity ID: {}", entityID);
                try {
                    roleDescriptors = provider.getRole(entityID, roleName);
                    if (roleDescriptors != null && !roleDescriptors.isEmpty()) {
                        break;
                    }
                } catch (MetadataProviderException e) {
                    log.warn("Error retrieving metadata from provider of type {}, proceeding to next provider",
                             provider.getClass().getName(), e);
                    continue;
                }
            }
        } finally {
            readLock.unlock();
        }

        return roleDescriptors;
    }

    /** {@inheritDoc} */
    public RoleDescriptor getRole(String entityID, QName roleName, String supportedProtocol)
        throws MetadataProviderException {
        Lock readLock = providerLock.readLock();
        readLock.lock();

        RoleDescriptor roleDescriptor = null;
        try {
            for (MetadataProvider provider : providers) {
                log.debug("Checking child metadata provider for entity descriptor with entity ID: {}", entityID);
                try {
                    roleDescriptor = provider.getRole(entityID, roleName, supportedProtocol);
                    if (roleDescriptor != null) {
                        break;
                    }
                } catch (MetadataProviderException e) {
                    log.warn("Error retrieving metadata from provider of type {}, proceeding to next provider",
                             provider.getClass().getName(), e);
                    continue;
                }
            }
        } finally {
            readLock.unlock();
        }

        return roleDescriptor;
    }

    /** {@inheritDoc} */
    public List<Observer> getObservers() {
        return observers;
    }

    /** {@inheritDoc} */
    public synchronized void destroy() {
        super.destroy();

        for(MetadataProvider provider : providers){
            if(provider instanceof BaseMetadataProvider){
                ((BaseMetadataProvider)provider).destroy();
            }
        }

        providers = Collections.emptyList();
        observers = Collections.emptyList();
    }

    /**
     * Convenience method for calling
     * {@link ObservableMetadataProvider.Observer#onEvent(MetadataProvider)} on
     * every registered Observer passing in this provider.
     */
    protected void emitChangeEvent() {
        if (observers == null || observers.size() == 0) {
            return;
        }

        List<Observer> tempObserverList = new ArrayList<Observer>(observers);
        for (Observer observer : tempObserverList) {
            if (observer != null) {
                observer.onEvent(this);
            }
        }
    }

    /**
     * Observer that clears the descriptor index of this provider.
     */
    private class ContainedProviderObserver implements Observer {

        /** {@inheritDoc} */
        public void onEvent(MetadataProvider provider) {
            emitChangeEvent();
        }
    }

    /** Class that wraps the currently list of providers and exposes it as an EntitiesDescriptors. */
    private class ChainingEntitiesDescriptor implements EntitiesDescriptor {

        @Nonnull
        @Override
        public LockableClassToInstanceMultiMap<Object> getObjectMetadata() {
            throw new UnsupportedOperationException();
        }

        /** Metadata from the child metadata providers. */
        private ArrayList<XMLObject> childDescriptors;

        /** Constructor. */
        public ChainingEntitiesDescriptor() {
            childDescriptors = new ArrayList<XMLObject>();

            Lock readLock = providerLock.readLock();
            readLock.lock();
            try {
                for (MetadataProvider provider : providers) {
                    childDescriptors.add(provider.getMetadata());
                }
            } catch (MetadataProviderException e) {
                log.error("Unable to get metadata from child metadata provider", e);
            } finally {
                readLock.unlock();
            }
        }

        /** {@inheritDoc} */
        public List<EntitiesDescriptor> getEntitiesDescriptors() {
            ArrayList<EntitiesDescriptor> descriptors = new ArrayList<EntitiesDescriptor>();
            for (XMLObject descriptor : childDescriptors) {
                if (descriptor instanceof EntitiesDescriptor) {
                    descriptors.add((EntitiesDescriptor) descriptor);
                }
            }

            return descriptors;
        }

        /** {@inheritDoc} */
        public List<EntityDescriptor> getEntityDescriptors() {
            ArrayList<EntityDescriptor> descriptors = new ArrayList<EntityDescriptor>();
            for (XMLObject descriptor : childDescriptors) {
                if (descriptor instanceof EntityDescriptor) {
                    descriptors.add((EntityDescriptor) descriptor);
                }
            }

            return descriptors;
        }

        /** {@inheritDoc} */
        public Extensions getExtensions() {
            return null;
        }

        /** {@inheritDoc} */
        public String getID() {
            return null;
        }

        /** {@inheritDoc} */
        public String getName() {
            return null;
        }

        /** {@inheritDoc} */
        public void setExtensions(Extensions extensions) {

        }

        /** {@inheritDoc} */
        public void setID(String newID) {

        }

        /** {@inheritDoc} */
        public void setName(String name) {

        }

        /** {@inheritDoc} */
        public String getSignatureReferenceID() {
            return null;
        }

        /** {@inheritDoc} */
        public Signature getSignature() {
            return null;
        }

        /** {@inheritDoc} */
        public boolean isSigned() {
            return false;
        }

        /** {@inheritDoc} */
        public void setSignature(Signature newSignature) {

        }

        /** {@inheritDoc} */
        public void addNamespace(Namespace namespace) {

        }

        /** {@inheritDoc} */
        public void detach() {

        }

        /** {@inheritDoc} */
        public Element getDOM() {
            return null;
        }

        /** {@inheritDoc} */
        public QName getElementQName() {
            return EntitiesDescriptor.DEFAULT_ELEMENT_NAME;
        }

        /** {@inheritDoc} */
        public IDIndex getIDIndex() {
            return null;
        }

        /** {@inheritDoc} */
        public NamespaceManager getNamespaceManager() {
            return null;
        }

        /** {@inheritDoc} */
        public Set<Namespace> getNamespaces() {
            return new LazySet<Namespace>();
        }

        /** {@inheritDoc} */
        public String getNoNamespaceSchemaLocation() {
            return null;
        }

        /** {@inheritDoc} */
        public List<XMLObject> getOrderedChildren() {
            ArrayList<XMLObject> descriptors = new ArrayList<XMLObject>();
            try {
                for (MetadataProvider provider : providers) {
                    descriptors.add(provider.getMetadata());
                }
            } catch (MetadataProviderException e) {
                log.error("Unable to generate list of child descriptors", e);
            }

            return descriptors;
        }

        /** {@inheritDoc} */
        public XMLObject getParent() {
            return null;
        }

        /** {@inheritDoc} */
        public String getSchemaLocation() {
            return null;
        }

        /** {@inheritDoc} */
        public QName getSchemaType() {
            return EntitiesDescriptor.TYPE_NAME;
        }

        /** {@inheritDoc} */
        public boolean hasChildren() {
            return !getOrderedChildren().isEmpty();
        }

        /** {@inheritDoc} */
        public boolean hasParent() {
            return false;
        }

        /** {@inheritDoc} */
        public void releaseChildrenDOM(boolean propagateRelease) {

        }

        /** {@inheritDoc} */
        public void releaseDOM() {

        }

        /** {@inheritDoc} */
        public void releaseParentDOM(boolean propagateRelease) {

        }

        /** {@inheritDoc} */
        public void removeNamespace(Namespace namespace) {

        }

        /** {@inheritDoc} */
        public XMLObject resolveID(String id) {
            return null;
        }

        /** {@inheritDoc} */
        public XMLObject resolveIDFromRoot(String id) {
            return null;
        }

        /** {@inheritDoc} */
        public void setDOM(Element dom) {

        }

        /** {@inheritDoc} */
        public void setNoNamespaceSchemaLocation(String location) {

        }

        /** {@inheritDoc} */
        public void setParent(XMLObject parent) {

        }

        /** {@inheritDoc} */
        public void setSchemaLocation(String location) {

        }

        /** {@inheritDoc} */
        public DateTime getValidUntil() {
            return null;
        }

        /** {@inheritDoc} */
        public boolean isValid() {
            return true;
        }

        /** {@inheritDoc} */
        public void setValidUntil(DateTime validUntil) {

        }

        /** {@inheritDoc} */
        public Long getCacheDuration() {
            return null;
        }

        /** {@inheritDoc} */
        public void setCacheDuration(Long duration) {

        }

        /** {@inheritDoc} */
        public Boolean isNil() {
            return Boolean.FALSE;
        }

        /** {@inheritDoc} */
        public XSBooleanValue isNilXSBoolean() {
            return new XSBooleanValue(Boolean.FALSE, false);
        }

        /** {@inheritDoc} */
        public void setNil(Boolean arg0) {
            // do nothing
        }

        /** {@inheritDoc} */
        public void setNil(XSBooleanValue arg0) {
            // do nothing
        }

    }
}