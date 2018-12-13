
How to run a simple sample of an Identity Provider (IDP) and Service Provider (SP)

**Step 1 - Get the Source** 

    git clone https://github.com/spring-projects/spring-security-saml.git
    cd spring-security-saml

**Step 2 - Start the Service Provider**

Service Provider runs on `http://localhost:8080/sample-sp`

    ./gradlew :spring-security-saml2-samples-boot-boot-config-sp:bootRun &

Please use

    username: user
    password: password
    
**Try it out**

***Againt a running SimpleSamlPHP Server***

* Spring Security SAML [as a Service Provider](http://localhost:8080/sample-sp)
* Spring Security SAML [as an initiating Service Provider](http://localhost:8080/sample-sp/saml/sp/discovery?idp=http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php)

Please use

    username: user
    password: password
