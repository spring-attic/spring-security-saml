/*
 * Copyright [2007] [University Corporation for Advanced Internet Development, Inc.]
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

package org.opensaml.common;

import org.opensaml.DefaultBootstrap;
import org.opensaml.PaosBootstrap;
import org.opensaml.xml.ConfigurationException;

/**
 * Extension to the default bootstrap process which sets up configuration for testing
 * purposes.
 */
public class BootstrapHelper extends DefaultBootstrap {
    
    /** List of XMLTooling configuration files with any needed test configuration. */
    private static String[] testConfigs = {  };
    
    /** {@inheritDoc} */
    public static synchronized void bootstrap() throws ConfigurationException {
        PaosBootstrap.bootstrap();
        
        initializeXMLTooling(testConfigs);
    }

}
