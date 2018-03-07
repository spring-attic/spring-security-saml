package org.springframework.security.saml.util;

import org.opensaml.common.binding.decoding.BasicURLComparator;
import org.opensaml.ws.transport.InTransport;

import java.util.List;

/**
 * Default implementation of {@link org.opensaml.common.binding.decoding.URIComparator} used in {@link SAMLUtil#getEndpoint(List, String, InTransport)}
 */
public class DefaultURLComparator extends BasicURLComparator {
    @Override
    public boolean compare(String uri1, String uri2) {
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
