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

package org.springframework.security.saml2.init;

import java.util.concurrent.atomic.AtomicBoolean;

public class SpringSecuritySaml {

    private static final SpringSecuritySaml INSTANCE = new OpenSamlConfiguration();

    public static SpringSecuritySaml getInstance() {
        return INSTANCE;
    }

    private final AtomicBoolean hasInitCompleted = new AtomicBoolean(false);


    public SpringSecuritySaml init() {
        if (!hasInitCompleted.get()) {
            performInit();
        }
        return this;
    }

    protected synchronized void performInit() {
        if (hasInitCompleted.compareAndSet(false, true)) {
            java.security.Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider()
            );
            ((OpenSamlConfiguration)this).bootstrap();
        }
    }





}
