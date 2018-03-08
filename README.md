# multitenant-sso-valve

Problem : 

Lets say your web applications come under a tenant space (a.com). Now, if you are fronting your application with a load balancer (e.g. Nginx) and a custom domain (custom.mine.com), you would not prefer to see the internal application server url at the browser. For example, if you expect your application url to be "custom.mine.com/foo", you would prefer to not show the original url "appserver.com/t/a.com/foo". 

Normally you can get around this problem by configuring a url rewrite at Nginx. But since the SSO flow is designed to go through a few redirects, you need to fix the problem in a different way. 

High-level Solution : 



This project is a clone of the default SAMLSSOValve shipped by default with WSO2 Application Server 5.3.0, and provides the following extra capabilities : 



Ability to read a Custom Assertion Consumer URL from the request headers : 

The request header names can be defined by adding the following 2 properties to AS_HOME/repository/conf/security/sso-sp-config.properties file : 

  # When the SSO application is fronted by an external domain, we need to switch the ACS url to that domain. 
  # This header can be added by any load balancer to the incoming first webapp request, 
  # so that the SAMLSSO Valve knows the correct ACS url. 
  CustomACSHeader=x-acs-url
  CustomRedirectDomainHeader=x-redirect-domain
  
 


