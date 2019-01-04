
How to run a simple sample of an Identity Provider (IDP) and Service Provider (SP)

**Step 1 - Get the Source** 

    git clone https://github.com/spring-projects/spring-security-saml.git
    cd spring-security-saml

**Step 2 - Start the Service Provider**

Service Provider runs on `http://localhost:8080/sample-sp`

    ./gradlew :spring-security-saml2-samples-boot-boot-config-sp:bootRun

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

**Sample Descriptions**

***Starter Sample***

The [Spring Boot Starter sample](boot/starter-sp) showcases the use of 
a Spring Boot application with the use of a minimal 
[default configuration](boot/starter-sp/src/main/java/org/springframework/security/saml/samples/SecurityConfig.java)
to configure the SAML Service Provider. 

Service Provider runs on `http://localhost:8080/sample-sp`

    ./gradlew :spring-security-saml2-samples-boot-starter-sp:bootRun

In order to have the sample run, we need to configure at least a private key/certificate
along with one remote Identity Provider (IDP). 

***Spring Boot with Configuration***

The [Spring Boot Configuration sample](boot/boot-config-sp) showcases the use of 
a Spring Boot [application.yml](boot/boot-config-sp/src/main/resources/application.yml) file
to configure the SAML Service Provider. The sample also uses 
[bean dependency injection](boot/boot-config-sp/src/main/java/org/springframework/security/saml/samples/SecurityConfig.java)
to configure all the SAML components  .

This sample also showcases the difference between SAML Single(federated) logout and local(server only) logout.

Service Provider runs on `http://localhost:8080/sample-sp`

    ./gradlew :spring-security-saml2-samples-boot-boot-config-sp:bootRun

***Java Only Configuration Sample***

The [Spring Boot sample](boot/java-config-sp) showcases the use of 
a Spring Boot application where all the configurations are set 
[programmatically]((boot/java-config-sp/src/main/java/org/springframework/security/saml/samples/SecurityConfig.java))
to configure the SAML Service Provider

Service Provider runs on `http://localhost:8080/sample-sp`

    ./gradlew :spring-security-saml2-samples-boot-java-config-sp:bootRun

***Java Only Configuration Sample***

The [Spring Boot sample](boot/java-config-sp) showcases the use of 
a Spring Boot application where all the configurations are set 
[programmatically]((boot/java-config-sp/src/main/java/org/springframework/security/saml/samples/SecurityConfig.java))
to configure the SAML Service Provider

Service Provider runs on `http://localhost:8080/sample-sp`

    ./gradlew :spring-security-saml2-samples-boot-java-config-sp:bootRun

***XML Configuration Sample***

The [Spring XML sample](boot/xml-config-sp) showcases the use of 
a Spring Boot application where all the beans are configured via
[an XML configuration file]((boot/xml-config-sp/src/main/resources/applicationContext.xml))
to configure the SAML Service Provider

Service Provider runs on `http://localhost:8080/sample-sp`

    ./gradlew :spring-security-saml2-samples-boot-xml-config-sp:bootRun
