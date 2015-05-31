/* Copyright 2010 Vladimir Schäfer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.saml.metadata;

import junit.framework.Assert;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.metadata.provider.AbstractReloadingMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import java.util.*;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;
import static org.junit.Assert.*;

/**
 * @author Vladimir Schäfer
 */
public class MetadataManagerTest {

    ApplicationContext context;
    MetadataManager manager;

    @Before
    public void initialize() throws Exception {
        String resName = "/" + getClass().getName().replace('.', '/') + ".xml";
        context = new ClassPathXmlApplicationContext(resName);
        manager = context.getBean("metadata", MetadataManager.class);
        manager.refreshMetadata();
    }

    /**
     * Test verifies that metadata defined in Spring descriptor are loaded correctly, including
     * EntityDescriptors defined as nested.
     *
     * @throws Exception error
     */
    @Test
    public void testParseMetadata() throws Exception {

        assertEquals("nest3", manager.getDefaultIDP());
        assertEquals("hostedSP", manager.getHostedSPName());

        assertEquals(4, manager.getIDPEntityNames().size());

        assertTrue(manager.getIDPEntityNames().contains("nest1"));
        assertTrue(manager.getIDPEntityNames().contains("nest2"));
        assertTrue(manager.getIDPEntityNames().contains("nest3"));
        assertTrue(manager.getIDPEntityNames().contains("http://localhost:8080/opensso"));

        assertEquals(1, manager.getSPEntityNames().size());
        assertTrue(manager.getSPEntityNames().contains("http://localhost:8081/spring-security-saml2-webapp"));

        assertNotNull(manager.getEntityDescriptor("nest1"));
        assertNotNull(manager.getEntityDescriptor("nest2"));
        assertNotNull(manager.getEntityDescriptor("nest3"));
        assertNotNull(manager.getEntityDescriptor("http://localhost:8080/opensso"));
        assertNotNull(manager.getEntityDescriptor("http://localhost:8081/spring-security-saml2-webapp"));
        assertNotNull(manager.getExtendedMetadata("hostedSP"));

        ExtendedMetadata extendedMetadata;

        extendedMetadata = manager.getExtendedMetadata("http://localhost:8081/spring-security-saml2-webapp");
        Assert.assertEquals("myAlias", extendedMetadata.getAlias());

        extendedMetadata = manager.getExtendedMetadata("nest1");
        Assert.assertEquals("myAliasDefault", extendedMetadata.getAlias());

        extendedMetadata = manager.getExtendedMetadata("nest2");
        Assert.assertEquals("nest2alias", extendedMetadata.getAlias());

        extendedMetadata = manager.getExtendedMetadata("nest3");
        Assert.assertEquals("myAliasDefault", extendedMetadata.getAlias());

        extendedMetadata = manager.getExtendedMetadata("http://localhost:8080/opensso");
        Assert.assertNull(extendedMetadata.getAlias());

    }

    /**
     * Verfies that null entityId can be used.
     *
     * @throws Exception error
     */
    @Test
    public void testNullEntityId() throws Exception {
        manager.getExtendedMetadata(null);
    }

    /**
     * Test performs concurrency tests on the metadata manager. It verifies whether updating the providers is reflected.
     *
     * @throws Exception error
     */
    @Test
    public void testMetadataRefresh() throws Exception {

        Timer metadataLoader;
        EntityVerifier entityVerifierExists, entityVerifierToFail;

        // Make sure the metadata is available
        metadataLoader = new Timer(true);
        entityVerifierExists = new EntityVerifier(Arrays.asList("nest1", "nest2", "nest3"), true);
        entityVerifierToFail = new EntityVerifier(Arrays.asList("http://localhost:8080/opensso"), true);
        metadataLoader.schedule(entityVerifierExists, 10l, 10l);
        metadataLoader.schedule(entityVerifierToFail, 10l, 10l);

        synchronized (this) {
            wait(500);
        }

        // Make sure the open sso metadata loader failed
        assertVerifiers(Arrays.asList(entityVerifierExists));
        assertVerifiers(Arrays.asList(entityVerifierToFail));

        // Remove an existing metadata
        manager.removeMetadataProvider(manager.getProviders().iterator().next());

        synchronized (this) {
            wait(500);
        }

        // Make sure the verifier failed
        assertVerifiers(Arrays.asList(entityVerifierExists));
        assertNotNull(entityVerifierToFail.getFailure());

        metadataLoader.cancel();

    }

    /**
     * A simple test putting the metadata manager under stress from a couple of threads while reloading it's content
     * at the same time.
     *
     * @throws Exception error
     */
    @Test
    public void testConcurrency() throws Exception {

        Timer metadataLoader = new Timer(true);
        List<EntityVerifier> verifiers = Arrays.asList(
                new EntityVerifier(Arrays.asList("nest1", "nest2", "nest3"), true),
                new EntityVerifier(Arrays.asList("nest1", "nest2", "nest3"), true),
                new EntityVerifier(Arrays.asList("nest1", "nest2", "nest3"), true),
                new EntityVerifier(Arrays.asList("nest1", "nest2", "nest3"), true),
                new EntityVerifier(Arrays.asList("nest1", "nest2", "nest3"), true)
        );

        for (EntityVerifier verifier : verifiers) {
            metadataLoader.schedule(verifier, 7l, 7l);
        }

        // Explicitly refreshing providers to add concurrency
        Timer refresher = new Timer(true);
        refresher.schedule(new TimerTask() {
            @Override
            public void run() {
                for (MetadataProvider metadataProvider : manager.getProviders()) {
                    try {
                        AbstractMetadataDelegate delegate = (AbstractMetadataDelegate) metadataProvider;
                        AbstractReloadingMetadataProvider prov = (AbstractReloadingMetadataProvider) delegate.getDelegate();
                        prov.refresh();
                    } catch (MetadataProviderException e) {
                        e.printStackTrace();
                    }
                }
            }
        }, 100l, 10l);

        Timer reloader = new Timer(true);
        MetadataReloader reloaderTask = new MetadataReloader();
        reloader.schedule(reloaderTask, 50l, 50l);

        synchronized (this) {
            wait(4000);
        }

        reloader.cancel();
        metadataLoader.cancel();

        System.out.println("Manager was reloaded " + reloaderTask.reloaded + " times");
        for (int i = 0; i < verifiers.size(); i++) {
            System.out.println("Verifier " + i + " was executed " + verifiers.get(i).getExecutions() + " times");
        }

        // Make sure the verifiers passed without problems
        assertVerifiers(verifiers);

        // Verify manager is not deadlocked and has correct data
        Set<String> idpEntityNames = manager.getIDPEntityNames();
        Set<String> spEntityNames = manager.getSPEntityNames();
        assertTrue(idpEntityNames.contains("nest1"));
        assertTrue(idpEntityNames.contains("nest2"));
        assertTrue(idpEntityNames.contains("nest3"));
        assertTrue(idpEntityNames.contains("http://localhost:8080/opensso"));
        assertTrue(spEntityNames.contains("http://localhost:8081/spring-security-saml2-webapp"));
        assertEquals(4, idpEntityNames.size());
        assertEquals(1, spEntityNames.size());
        assertEquals(3, manager.getAvailableProviders().size());

    }

    /**
     * Test verifies that new metadata provider can be added after manager has already been created.
     *
     * @throws Exception error
     */
    @Test
    public void testMetadataChanges() throws Exception {

        MetadataProvider newProvider = context.getBean("singleProvider", MetadataProvider.class);
        assertNull(manager.getEntityDescriptor("http://localhost:8080/noBinding"));

        manager.addMetadataProvider(newProvider);
        manager.refreshMetadata();
        assertNotNull(manager.getEntityDescriptor("http://localhost:8080/noBinding"));

        boolean found = false;
        for (ExtendedMetadataDelegate provider : manager.getAvailableProviders()) {
            if (newProvider.equals(provider) || newProvider.equals(provider.getDelegate())) {
                found = true;
                break;
            }
        }
        assertTrue("Added provider wasn't found in the list of active providers", found);

        manager.removeMetadataProvider(newProvider);
        manager.refreshMetadata();
        assertNull(manager.getEntityDescriptor("http://localhost:8080/noBinding"));

    }

    private class MetadataReloader extends TimerTask {

        // State of the refresh flag during last execution
        private boolean lastState;

        // Number of times the manager was reloaded
        private int reloaded = 0;

        private MetadataReloader() {
            this.lastState = manager.isRefreshRequired();
        }

        @Override
        public void run() {
            boolean state = manager.isRefreshRequired();
            if (state != lastState) {
                reloaded++;
            }
            manager.setRefreshRequired(true);
            lastState = true;
        }

        public int getReloaded() {
            return reloaded;
        }

    }

    private void assertVerifiers(List<EntityVerifier> verifiers) throws Exception {

        for (EntityVerifier verifier : verifiers) {

            assertTrue(verifier.getExecutions() > 0);
            if (verifier.getFailure() != null) {
                throw new RuntimeException(verifier.getFailure());
            }

        }

    }

    private class EntityVerifier extends TimerTask {

        private boolean present;
        private List<String> entites;
        private Throwable failure;
        private int executions = 0;

        private EntityVerifier(List<String> entites, boolean present) {
            this.entites = entites;
            this.present = present;
        }

        @Override
        public void run() {

            try {

                executions++;

                for (String entity : entites) {

                    if (present) {
                        assertNotNull(manager.getEntityDescriptor(entity));
                        assertNotNull(manager.getExtendedMetadata(entity));
                        assertTrue(manager.getIDPEntityNames().contains(entity) || manager.getSPEntityNames().contains(entity));
                    } else {
                        assertNull(manager.getEntityDescriptor(entity));
                    }

                }

            } catch (MetadataProviderException e) {
                failure = e;
                throw new RuntimeException("Timer has failed", e);
            } catch (Throwable e) {
                failure = e;
                throw new RuntimeException("Timer has failed", e);
            }

        }

        public Throwable getFailure() {
            return failure;
        }

        public int getExecutions() {
            return executions;
        }

    }

}
