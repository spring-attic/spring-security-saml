/* Copyright 2009 Vladimir Schäfer
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
package org.springframework.security.saml;

import org.junit.Before;
import org.junit.BeforeClass;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.springframework.security.saml.parser.ParserPoolHolder;

import javax.xml.parsers.DocumentBuilderFactory;

/**
 * @author Vladimir Schäfer
 */
public class SAMLTestBase {

    public static XMLObjectBuilderFactory builderFactory;

    @BeforeClass
    public static void initializeOpenSAML() throws Exception {
        DocumentBuilderFactory newFactory = DocumentBuilderFactory.newInstance();
        System.out.println(newFactory.getClass().getName());
        DefaultBootstrap.bootstrap();
        builderFactory = Configuration.getBuilderFactory();
    }

    @Before
    public void initializePool() {
        BasicParserPool pool = new BasicParserPool();
        ParserPoolHolder holder = new ParserPoolHolder(pool);
    }
}