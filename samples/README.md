
How to run a simple sample of an Identity Provider (IDP) and Service Provider (SP)

**Step 1 - Get the Source** 

    git clone https://github.com/spring-projects/spring-security-saml.git
    cd spring-security-saml

**Step 2 - Start the Service Provider**

Service Provider runs on `http://localhost:8080/sample-sp`

    ./gradlew :spring-security-saml2-samples-service-provider-boot-config:bootRun

Please use

    username: user
    password: password
    
**Try it out**

***Against a running SimpleSamlPHP Server***

* Spring Security SAML [as a Service Provider](http://localhost:8080/sample-sp)
* Spring Security SAML [as an initiating Service Provider](http://localhost:8080/sample-sp/saml/sp/authenticate?idp=http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php)

Please use

    username: user
    password: password

**Sample Descriptions**

***Starter Sample***

The [Spring Boot Starter sample](service-provider/starter) showcases the use of 
a Spring Boot application with the use of a minimal 
[default configuration](service-provider/starter/src/main/java/org/springframework/security/saml/samples/SecurityConfig.java)
to configure the SAML Service Provider. 

Service Provider runs on `http://localhost:8080/sample-sp`

    ./gradlew :spring-security-saml2-samples-service-provider-starter:bootRun

In order to have the sample run, we need to configure at least a private key/certificate
along with one remote Identity Provider (IDP). 

***Spring Boot with Configuration***

The [Spring Boot Configuration sample](service-provider/boot-config) showcases the use of 
a Spring Boot [application.yml](service-provider/boot-config/src/main/resources/application.yml) file
to configure the SAML Service Provider. The sample also uses 
[bean dependency injection](service-provider/boot-config/src/main/java/org/springframework/security/saml/samples/SecurityConfig.java)
to configure all the SAML components  .

This sample also showcases the difference between SAML Single(federated) logout and local(server only) logout.

Service Provider runs on `http://localhost:8080/sample-sp`

    ./gradlew :spring-security-saml2-samples-service-provider-boot-config:bootRun

***Java Only Configuration Sample***

The [Spring Boot sample](service-provider/java-config) showcases the use of 
a Spring Boot application where all the configurations are set 
[programmatically]((service-provider/java-config/src/main/java/org/springframework/security/saml/samples/SecurityConfig.java))
to configure the SAML Service Provider

Service Provider runs on `http://localhost:8080/sample-sp`

    ./gradlew :spring-security-saml2-samples-service-provider-java-config:bootRun

***Java Only Configuration Sample***

The [Spring Boot sample](service-provider/java-config) showcases the use of 
a Spring Boot application where all the configurations are set 
[programmatically]((service-provider/java-config/src/main/java/org/springframework/security/saml/samples/SecurityConfig.java))
to configure the SAML Service Provider

Service Provider runs on `http://localhost:8080/sample-sp`

    ./gradlew :spring-security-saml2-samples-service-provider-java-config:bootRun

***XML Configuration Sample***

The [Spring XML sample](service-provider/xml-config) showcases the use of 
a Spring Boot application where all the beans are configured via
[an XML configuration file]((service-provider/xml-config/src/main/resources/applicationContext.xml))
to configure the SAML Service Provider

Service Provider runs on `http://localhost:8080/sample-sp`

    ./gradlew :spring-security-saml2-samples-service-provider-xml-config:bootRun
