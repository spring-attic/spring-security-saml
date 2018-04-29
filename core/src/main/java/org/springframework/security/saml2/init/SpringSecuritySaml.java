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

import javax.xml.datatype.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import org.springframework.security.saml2.Saml2Object;
import org.springframework.security.saml2.metadata.Binding;
import org.springframework.security.saml2.metadata.Endpoint;
import org.springframework.security.saml2.spi.opensaml.OpenSamlConfiguration;
import org.springframework.security.saml2.xml.SimpleKey;
import org.springframework.web.util.UriComponentsBuilder;

public abstract class SpringSecuritySaml<T extends SpringSecuritySaml> {

    private static final SpringSecuritySaml INSTANCE = new OpenSamlConfiguration();

    public static SpringSecuritySaml getInstance() {
        return INSTANCE;
    }

    private final AtomicBoolean hasInitCompleted = new AtomicBoolean(false);


    @SuppressWarnings("checked")
    public T init() {
        if (!hasInitCompleted.get()) {
            performInit();
        }
        return (T) this;
    }

    protected synchronized void performInit() {
        if (hasInitCompleted.compareAndSet(false, true)) {
            java.security.Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider()
            );
            bootstrap();
        }
    }

    public static long durationToMillis(Duration duration) {
        return getInstance()
            .init()
            .toMillis(duration);
    }

    public static Duration millisToDuration(long millis) {
        return getInstance()
            .init()
            .toDuration(millis);
    }

    protected abstract void bootstrap();

    public abstract long toMillis(Duration duration);

    public abstract Duration toDuration(long millis);

    public abstract String toXml(Saml2Object saml2Object);

    public abstract Saml2Object resolve(String xml, List<SimpleKey> trustedKeys);


    public Endpoint getEndpoint(String baseUrl, String path, Binding binding, int index, boolean isDefault) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(baseUrl);
        builder.pathSegment(path);
        return getEndpoint(builder.build().toUriString(), binding, index, isDefault);
    }

    public Endpoint getEndpoint(String url, Binding binding, int index, boolean isDefault) {
        return
            new Endpoint()
                .setIndex(index)
                .setBinding(binding)
                .setLocation(url)
                .setDefault(isDefault)
                .setIndex(index);
    }
}
