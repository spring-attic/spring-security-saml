package org.springframework.security.saml.util;


import javax.annotation.Nullable;
import java.util.List;

import net.shibboleth.utilities.java.support.net.BasicURLComparator;
import net.shibboleth.utilities.java.support.net.URIComparator;
import net.shibboleth.utilities.java.support.net.URIException;

/**
 * Default implementation of {@link URIComparator} used in {@link SAMLUtil#getEndpoint(List, String, InTransport)}
 */
public class DefaultURLComparator extends BasicURLComparator {

    @Override
    public boolean compare(@Nullable final String uri1, @Nullable String uri2) throws URIException {
        if (uri2 == null){
            return uri1 == null;
        }
        int queryStringIndex = uri2.indexOf('?');
        if (queryStringIndex >= 0){
            uri2 = uri2.substring(0, queryStringIndex);// removing query string to keep behavior of SAMLUtil.getEndpoint(List, String, InTransport) unchanged
        }
        return super.compare(uri1, uri2);
    }
}
