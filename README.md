# sproutfx-security-oauth-spring-boot-starter
---
### Related dependencies
logback & logstash  

### Deploy configuration
- Maven settings.xml  
    ```xml
    <server>
    	<id> platform-release </id>
    	<username> release-repository-user-name </username>
    	<password> release-repository-user-password </password>
    </server>
    
    <server>
    	<id> platform-snapshot </id>
    	<username> snapshot-repository-user-name </username>
    	<password> snaphost-repository-user-password </password>
    </server>
    ```

### Configuration
```YAML
# configuration
sproutfx:
  security:
    authorization:
      header: {String} header property name where token data located
      type: {String} token type
      provider-code: {String} authorization provider code
      client-code: {String} authorization client code
      access-token-secret: {String} encrypted access token secret
    web:
      ignore:
        patterns:
          - {String} patterns for ignore security
        
    http:
      authorize-requests:
        permit-all:
          patterns:
            - {String} uri patterns for api access right : permit all Http request
        permit-get:
          patterns:
            - {String} uri patterns for api access right : permit only GET method http request
        permit-post:
          patterns:
            - {String} uri patterns for api access right : permit only POST method http request
        permit-put: 
          patterns:
            - {String} uri patterns for api access right : permit only PUT method http request
        permit-delete:
          patterns:
            - {String} uri patterns for api access right : permit only DELETE method http request
```