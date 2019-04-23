# Proof of Concept - MVP - SAML Service Provider

Sample platform to test out different concepts 
for how to implement a SAML Service Provider (SP)

## Functionality Supported

### Metadata

Metadata is inherent part. Most metadata can be generated statically 
based on a few attributes such as

* Entity ID - a unique identifier for a Service Provider, most common a URL
* Private Key and a Certificate - Used for signing and encryption of SAML messages
* Assertion Consumer Endpoints (ACS) - HTTP endpoints that accept SAML messages 
containing assertions (authentications)

This sample generates metadata based on this registration combined with context data
from the HTTP request. The entity ID and ACS endpoints are dynamically generated 
based on the incoming HTTP Host header and the application context path

### Authentication

The sample is able to receive an assertion, unsigned, signed or encrypted, and authenticate 
the user in the local application based on mutual trust with the identity provider. (IDP) 

## Showcase

### Test Support

SAML, which requires, mutual registration between an identity provider, IDP, and a 
service provider, SP, is often difficult to test. Some applications rely on 
integration tests using external SAML providers making the test dependent on external factors to succeed.

Test driven development is a desired feature that we wish to highlight.

### Spring Boot Configuration

### Independent SAML Core Library
