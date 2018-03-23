/*
 * Copyright 2010 Jonathan Tellier
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.opensaml;


import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLConfigurator;
import org.opensaml.xmlsec.config.JavaCryptoValidationInitializer;

public class PaosBootstrap {

    /** XMLTooling configuration file for PAOS binding */
    private static String paosXmlToolingConfig = "/liberty-paos-config.xml";

    public static synchronized PaosBootstrap bootstrap() throws Exception {
        new JavaCryptoValidationInitializer().init();
        InitializationService.initialize();
        XMLConfigurator configurator = new XMLConfigurator();
        configurator.load(PaosBootstrap.class.getResourceAsStream(paosXmlToolingConfig));
//        DefaultBootstrap.bootstrap();
//        DefaultBootstrap.initializeXMLTooling(paosXmlToolingConfig);
        return new PaosBootstrap();
    }

    public static BasicParserPool createParserPool() throws ComponentInitializationException {
        BasicParserPool pool = new BasicParserPool();
        pool.setNamespaceAware(true);
        pool.initialize();
        return pool;
    }

}
