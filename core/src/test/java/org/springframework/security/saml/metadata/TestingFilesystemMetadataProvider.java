package org.springframework.security.saml.metadata;

import org.joda.time.DateTime;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;

import java.io.File;
import java.util.Timer;

/**
 * Provider which constantly refreshes itself.
 */
public class TestingFilesystemMetadataProvider extends FilesystemMetadataProvider {

    public TestingFilesystemMetadataProvider(File metadata) throws MetadataProviderException {
        super(metadata);
    }

    public TestingFilesystemMetadataProvider(Timer backgroundTaskTimer, File metadata) throws MetadataProviderException {
        super(backgroundTaskTimer, metadata);
    }

    @Override
    public DateTime getLastRefresh() {
        return null;
    }

}
