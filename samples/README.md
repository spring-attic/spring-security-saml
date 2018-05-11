
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

This sample supports [SP initiated login](http://localhost:8080/sample-sp)
and [IDP initiated login](http://localhost:8081/sample-idp/saml/idp/init?sp=http://localhost:8080/sample-sp)

Please use

    username: testuser
    password: testpassword

