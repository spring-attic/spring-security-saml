package org.springframework.security.saml.saml2;

public class ImplementationHolder implements Saml2Object {

    private Object implementation;

    public Object getImplementation() {
        return implementation;
    }

    public ImplementationHolder setImplementation(Object implementation) {
        this.implementation = implementation;
        return this;
    }
}
