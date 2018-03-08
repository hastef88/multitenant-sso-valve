# multitenant-sso-valve

Problem : 

Lets say your web applications come under a tenant space (a.com). Now, if you are fronting your application with a load balancer (e.g. Nginx) and a custom domain (custom.mine.com), you would not prefer to see the internal application server url at the browser. For example, if you expect your application url to be "custom.mine.com/foo", you would prefer to not show the original url "appserver.com/t/a.com/foo". 

Normally you can get around this problem by configuring a URL rewrite at Nginx. But since the SSO flow is designed to go through a few redirects, you need to fix the problem in a different way. 

High-level Solution : 

The ideal SSO flow can be explained in terms of browser navigation as follows (considering WSO2 implementation) : 

1.  Request - custom.mine.com/foo
    Response - 302 redirect -> identityserver/samlsso + JSESSION cookie with "custom.mine.com" domain and "/foo" path.

2.  Request - identityserver/samlsso
    Response - 302 redirect -> identityserver/commonauth 

3.  Request - identityserver/commonauth 
    Response - 302 redirect -> identityserver/loginPage 

4.  Request - identityserver/loginPage 
    Response - identityserver/loginPage is loaded. 

    ** After entering credentials 
5.  Request - identityserver/commonauth + credentials
    Response - 302 redirect -> identityserver/samlsso

6.  Request - identityserver/samlsso
    Response - temporary identityserver/samlsso page is loaded until redirection to Assertion Consumer url. 

7.  Request - custom.mine.com/foo/acs ** ACS url + JSESSION cookie since it contains the matching domain and path.
    Response - 302 redirect custom.mine.com/foo

Role of MultiTenantSSOValve : 

This project is a clone of the default SAMLSSOValve shipped by default with WSO2 Application Server 5.3.0, and provides the following extra capabilities : 

1. Ability to read a Custom Assertion Consumer URL from the request headers : 

    The request header names can be defined by adding the following 2 properties to AS_HOME/repository/conf/security/sso-sp-  config.properties file : 

      // When the SSO application is fronted by an external domain, we need to switch the ACS url to that domain. 
      // This header can be added by any load balancer to the incoming first webapp request, 
      // so that the SAMLSSO Valve knows the correct ACS url. 
      CustomACSHeader=x-acs-url
      CustomRedirectDomainHeader=x-redirect-domain
      
   With this, if we set above "x-acs-url" and "x-redirect-domain" as custom headers in Nginx, the Valve will set the ACS url based on them. 
   
 2. Ability to Skip certain URIs from SSO flow on a per-webapp basis. 
 
   This valve honors any URIs configured under the "sso.skip.uris" context property in a web application's web.xml, and skips such URls from the SSO flow. 
   
   ```xml
   <context-param>
        <param-name>sso.skip.uris</param-name>
        <param-value>/t/a.com/webapps/foo/iamaskipuri</param-value>
   </context-param>
   ```

   
 Other configurations required for the overall scenario to work : 
 
 1. You will need an Nginx route similar to the following : 
 
 ```yaml
      location /foo/ {
	proxy_pass https://appserver.com/t/a.com/webapps/foo/; #Route to send the request.
	proxy_set_header X-ACS-URL "https://custom.mine.com/foo/acs"; # Custom HTTP Header to communicate the ACS url to appserver. 
	proxy_set_header        X-REDIRECT-DOMAIN "custom.mine.com"; # Custom HTTP Header to communicate the redirect domain to appserver. 
	proxy_pass_request_headers      on;	# Instruct Nginx to pass above custom headers. 
	proxy_cookie_domain     appserver.com custom.mine.com; # In order to switch the domain of the cookies in response.
	proxy_cookie_path       /t/a.com/webapps/foo /foo; # In order to switch the path of the cookies in response.
      }
      ```
      
  2. Set the custom assertion URL at the identity service provider.
  
  3. By default the tomcat container does not set a domain to the JSESSION cookie, and this causes the above "proxy_cookie_domain" directive to not be executed in Nginx. So, to enforce the appserver domain, we must add the  sessionCookieDomain="appserver.com" attribute to the context tag in AS_HOME/repository/conf/tomcat/context.xml. 
 
  
 
  
  
  
 


