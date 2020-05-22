package org.springframework.security.saml.metadata;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.xml.parse.ParserPool;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.security.saml.key.KeyManager;

import java.io.File;

import static junit.framework.Assert.assertNotNull;

public class MetadataManagerWithTLSConfigurer {

	ApplicationContext context;
	KeyManager keyManager;
	MetadataManager manager;
	ParserPool pool;

	@Before
	public void initialize() throws Exception {
		String resName = "/" + getClass().getName().replace('.', '/') + ".xml";
		context = new ClassPathXmlApplicationContext(resName);
		keyManager = context.getBean("keyManager", KeyManager.class);
		manager = context.getBean("metadata", MetadataManager.class);
		pool = context.getBean("parserPool", ParserPool.class);
	}

	@Test
	public void testExplicitKeyStore() throws Exception {
		ExtendedMetadataDelegate provider = getMetadata("classpath:testSP_signed_ca2_chain.xml");
		provider.setMetadataRequireSignature(true);
		provider.setMetadataTrustCheck(true);
		provider.setForceMetadataRevocationCheck(true);

		manager.addMetadataProvider(provider);
		manager.refreshMetadata();

		assertNotNull(manager.getEntityDescriptor("test_ca2"));

	}

	protected ExtendedMetadataDelegate getMetadata(String fileName) throws Exception {
		File file = context.getResource(fileName).getFile();
		FilesystemMetadataProvider innerProvider = new FilesystemMetadataProvider(file);
		innerProvider.setParserPool(pool);
		return new ExtendedMetadataDelegate(innerProvider);
	}


}
