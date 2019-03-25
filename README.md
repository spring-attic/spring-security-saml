# Spring SAML

[![Build Status](https://travis-ci.org/spring-projects/spring-security-saml.svg?branch=develop)](https://github.com/spring-projects/spring-security-saml/)

## Upgrade note

This project is being rewritten. There is a base implementation in the 
[develop](https://github.com/spring-projects/spring-security-saml/tree/develop) including 
milestone releases in the [milestone](https://repo.spring.io/milestone/org/springframework/security/extensions/spring-security-saml2-core/)
repository.

In the [develop-3.0](https://github.com/spring-projects/spring-security-saml/tree/develop) branch we are creating a 
solution that builds on top of the milestones and is better aligned with Spring Security.
The intent with this branch is to merge it with the [Spring Security](https://github.com/spring-projects/spring-security) 
project and release as part of Spring Security core.

For that reason, we will not be publishing any official releases of the 2.0.0 milestones, but will maintain it
until all feature functionality that exists in the milestones are part of Spring Security.

We continue to accept pull request for the 1.0.x branch, but are not actively developing it.

## Introduction

Spring SAML Extension allows seamless inclusion of SAML 2.0 Service Provider capabilities in Spring applications. All products supporting SAML 2.0 in Identity Provider mode (e.g. ADFS 2.0, Shibboleth, OpenAM/OpenSSO, Ping Federate, Okta) can be used to connect with Spring SAML Extension.

## Code of Conduct
This project adheres to the Contributor Covenant [code of conduct](CODE_OF_CONDUCT.md).
By participating, you are expected to uphold this code. Please report unacceptable behavior to spring-code-of-conduct@pivotal.io.

## Links 
Web:
https://projects.spring.io/spring-security-saml/

Sources: https://github.com/spring-projects/spring-security-saml
Documentation: https://docs.spring.io/spring-security-saml/docs/1.0.x-SNAPSHOT/reference/
Jira: https://jira.spring.io/browse/SES/component/10711/
CI: https://build.springsource.org/browse/SES

Releases:
Final: https://repo.spring.io/list/release/org/springframework/security/extensions/
Milestone: https://repo.spring.io/list/milestone/org/springframework/security/extensions/
Snapshot: https://repo.spring.io/list/snapshot/org/springframework/security/extensions/

Support:
Stackoverflow: https://stackoverflow.com/questions/tagged/spring-saml
Forum: https://forum.spring.io/forum/spring-projects/security/saml
Commercial: vladimir@v7security.com

Online demo: https://saml-federation.appspot.com/
