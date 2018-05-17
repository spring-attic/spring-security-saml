
How to run a simple sample of an Identity Provider (IDP) and Service Provider (SP)

**Step 1 - Get the Source** 

    git clone https://github.com/spring-projects/spring-security-saml.git
    cd spring-security-saml

**Step 2 - Start the Service Provider**

Service Provider runs on `http://localhost:8080/sample-sp`

    ./gradlew :spring-security-saml-samples/boot/simple-service-provider:bootRun &

**Step 3 - Start the Identity Provider**

Service Provider runs on `http://localhost:8081/sample-idp`

    ./gradlew :spring-security-saml-samples/boot/simple-identity-provider:bootRun &
    
**Try it out**

***Local to local***
This sample supports [SP initiated login](http://localhost:8080/sample-sp)
and [IDP initiated login](http://localhost:8081/sample-idp/saml/idp/init?sp=http://localhost:8080/sample-sp)

***Againt a running SimpleSamlPHP Server***

* Spring Security SAML [as a Service Provider](http://localhost:8080/sample-sp)
* Spring Security SAML [as an initiating Service Provider](http://localhost:8080/sample-sp/saml/sp/discovery?idp=http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php)
* Spring Security SAML [as an identity provider](http://simplesaml-for-spring-saml.cfapps.io/module.php/saml/disco.php?entityID=http%3A%2F%2Fsimplesaml-for-spring-saml.cfapps.io%2Fmodule.php%2Fsaml%2Fsp%2Fmetadata.php%2Fdefault-sp&return=http%3A%2F%2Fsimplesaml-for-spring-saml.cfapps.io%2Fmodule.php%2Fsaml%2Fsp%2Fdiscoresp.php%3FAuthID%3D_76ff38b7d741d37b828c917b6f2ed70cde863123c7%253Ahttp%253A%252F%252Fsimplesaml-for-spring-saml.cfapps.io%252Fmodule.php%252Fcore%252Fas_login.php%253FAuthId%253Ddefault-sp%2526ReturnTo%253Dhttp%25253A%25252F%25252Fsimplesaml-for-spring-saml.cfapps.io%25252Fmodule.php%25252Fcore%25252Fauthenticate.php%25253Fas%25253Ddefault-sp&returnIDParam=idpentityid)
* Spring Security SAML [initiating as an identity provider](http://localhost:8081/sample-idp/saml/idp/init?sp=http://simplesaml-for-spring-saml.cfapps.io/module.php/saml/sp/metadata.php/default-sp).
  Redirect after authentication is currently not working, check that you're logged in at the [Simple Saml PHP user page](http://simplesaml-for-spring-saml.cfapps.io/module.php/core/authenticate.php?as=default-sp)

Please use

    username: testuser
    password: testpassword

