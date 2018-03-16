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

import org.opensaml.xml.util.AbstractWrappedSingletonFactory;

/**
 * Singleton factory for producing instances of {@link MetadataCredentialResolver}
 * based on a given instance of {@link MetadataProvider}.
 *
 * <p>
 * Only once instance of a metadata credential resolver will exist for
 * each metadata provider instance.
 * </p>
 */
public class MetadataCredentialResolverFactory
    extends AbstractWrappedSingletonFactory<MetadataProvider, MetadataCredentialResolver> {

    /** The global instance of the factory itself. */
    private static MetadataCredentialResolverFactory factory;

    /**
     * Constructor.
     *
     * This constructor hides the superclass public constructor, forcing
     * the single, global factory instance to be obtained from {@link #getFactory()}.
     *
     */
    protected MetadataCredentialResolverFactory() {
        super();
    }

    /**
     * Return the global factory instance.
     *
     * @return the global factory instance
     */
    public static synchronized MetadataCredentialResolverFactory getFactory() {
        if (factory == null) {
            factory = new MetadataCredentialResolverFactory();
        }
        return factory;
    }

    /** {@inheritDoc} */
    protected MetadataCredentialResolver createNewInstance(MetadataProvider metadataProvider) {
        return new MetadataCredentialResolver(metadataProvider);
    }

}
