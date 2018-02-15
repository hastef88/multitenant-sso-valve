/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.webapp.mgt.sso.custom;

import org.apache.catalina.authenticator.SingleSignOn;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.sso.agent.SSOAgentConstants;
import org.wso2.carbon.identity.sso.agent.SSOAgentException;
import org.wso2.carbon.identity.sso.agent.SSOAgentRequestResolver;
import org.wso2.carbon.identity.sso.agent.bean.LoggedInSessionBean;
import org.wso2.carbon.identity.sso.agent.bean.SSOAgentConfig;
import org.wso2.carbon.identity.sso.agent.saml.SAML2SSOManager;
import org.wso2.carbon.identity.sso.agent.saml.SSOAgentCarbonX509Credential;
import org.wso2.carbon.identity.sso.agent.saml.SSOAgentX509Credential;
import org.wso2.carbon.identity.sso.agent.util.SSOAgentUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.carbon.webapp.mgt.sso.RelayState;
import org.wso2.carbon.webapp.mgt.sso.SSOUtils;
import org.wso2.carbon.webapp.mgt.sso.WebappSSOConstants;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

/**
 * SSO Valve to support reading specific SSO configurations (e.g. skipurls, redirect urls) from different
 * files located tenant+webapp path.
 */
public class MultiTenantSAMLSSOValve extends SingleSignOn {

    private static Log log = LogFactory.getLog(MultiTenantSAMLSSOValve.class);
    private static final String MEDIA_TYPE_TEXT_HTML = "text/html";
    private static final String ENABLE_SAML2_SSO_WITH_TENANT = "enable.saml2.sso.with.tenant";
    private Properties ssoSPConfigProperties = new Properties();

    private ConcurrentHashMap<String, String> tenantDomainMap;

    public MultiTenantSAMLSSOValve() throws IOException {
        log.info("Initializing SAMLSSOValve..");
        tenantDomainMap = new ConcurrentHashMap<>();

        //Read generic SSO ServiceProvider details
        if (SSOUtils.isSSOSPConfigExists()) {
            try ( FileInputStream fileInputStream = new FileInputStream(WebappSSOConstants.SSO_SP_CONFIG_PATH)) {
                ssoSPConfigProperties.load(fileInputStream);
                log.info("Successfully loaded SSO SP Config.");
            }
        } else {
            throw new FileNotFoundException("Unable to find SSO SP config properties file in" +
                    WebappSSOConstants.SSO_SP_CONFIG_PATH);
        }
    }

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {

        if (log.isDebugEnabled()) {
            log.debug("Invoking SAMLSSOValve. Request URI : " + request.getRequestURI());
        }
        //Is enable SSO Valve defined in context param?
        if (!Boolean.parseBoolean(request.getContext().findParameter(WebappSSOConstants.ENABLE_SAML2_SSO))) {
            if (log.isDebugEnabled()) {
                log.debug("Saml2 SSO not enabled in webapp " + request.getContext().getName());
            }
            getNext().invoke(request, response);
            return;
        }

        SSOAgentConfig ssoAgentConfig =
                (SSOAgentConfig) request.getSessionInternal().getNote(WebappSSOConstants.SSO_AGENT_CONFIG);

        if (ssoAgentConfig == null) {
            try {
                //Create SSOAgentConfig
                ssoAgentConfig = new SSOAgentConfig();
                ssoAgentConfig.initConfig(ssoSPConfigProperties);

                String tenantDomain = MultitenantUtils.getTenantDomain(request);
                int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();

                SSOAgentX509Credential ssoAgentX509Credential =
                        new SSOAgentCarbonX509Credential(tenantId, tenantDomain);
                ssoAgentConfig.getSAML2().setSSOAgentX509Credential(ssoAgentX509Credential);
                ssoAgentConfig.getSAML2().setSPEntityId(SSOUtils.generateIssuerID(request.getContextPath()));


                // Priority to request header identified by SSO-SP-CONFIG Property "CustomACSHeaderName", second the Appserver
                // property.
                String acsUrl = MultiTenantSSOUtils.generateConsumerUrl(request, ssoSPConfigProperties);

                cacheRedirectDomain(request);

                //todo remove
//                acsUrl = SSOUtils.generateConsumerUrl(request.getContextPath(), ssoSPConfigProperties);

                if (log.isDebugEnabled()) {
                    log.debug("Setting ACS_URL to : " + acsUrl);
                }

                ssoAgentConfig.getSAML2().setACSURL(acsUrl);

                ssoAgentConfig.verifyConfig();

                String ssoTenantDomain = request.getContext().findParameter(ENABLE_SAML2_SSO_WITH_TENANT);
                if (ssoTenantDomain != null && !ssoTenantDomain.isEmpty()) {
                    ssoAgentConfig.getQueryParams().put(MultitenantConstants.TENANT_DOMAIN,
                            new String[]{ssoTenantDomain});
                }

                if (log.isDebugEnabled()) {
                    log.debug("Creating SSOAgentConfig, IssuerId=" + ssoAgentConfig.getSAML2().getSPEntityId()
                            + ", CurrentTenant=" + tenantDomain + ", SSOTenant=" + ssoTenantDomain);
                }

                request.getSessionInternal().setNote(WebappSSOConstants.SSO_AGENT_CONFIG, ssoAgentConfig);
            } catch (Exception e) {
                log.error("Error on initializing SAML2SSOManager", e);
                return;
            }
        }

        try {

            SSOAgentRequestResolver resolver =
                    new SSOAgentRequestResolver(request, response, ssoAgentConfig);

            if (resolver.isURLToSkip()) {
                if (log.isDebugEnabled()) {
                    log.debug("Request matched a skip URL. Skipping..");
                }
                getNext().invoke(request, response);
                return;
            }

            SAML2SSOManager samlSSOManager;
            if (resolver.isSLORequest()) {

                if (log.isDebugEnabled()) {
                    log.debug("Processing Single Log Out Request");
                }
                samlSSOManager = new SAML2SSOManager(ssoAgentConfig);
                samlSSOManager.doSLO(request);

            } else if (resolver.isSAML2SSOResponse()) {

                if (log.isDebugEnabled()) {
                    log.debug("Processing SSO Response.");
                }

                samlSSOManager = new SAML2SSOManager(ssoAgentConfig);
                try {
                    // Read the redirect path. This has to read before the session get invalidated as it first
                    // tries to read the redirect path form the session attribute
                    String redirectPath = readAndForgetRedirectPathAfterSLO(request);

                    samlSSOManager.processResponse(request, response);
                    //redirect according to relay state attribute
                    String relayStateId = ssoAgentConfig.getSAML2().getRelayState();
                    if (relayStateId != null && request.getSession(Boolean.FALSE) != null) {
                        RelayState relayState = (RelayState) request.getSession(Boolean.FALSE).getAttribute(relayStateId);
                        if (relayState != null) {
                            request.getSession(Boolean.FALSE).removeAttribute(relayStateId);

                            String requestedURI = relayState.getRequestedURL();
                            if (relayState.getRequestQueryString() != null) {
                                requestedURI = requestedURI.concat("?").concat(relayState.getRequestQueryString());
                            }
                            if (relayState.getRequestParameters() != null) {
                                request.getSession(Boolean.FALSE).setAttribute("REQUEST_PARAM_MAP",
                                        relayState.getRequestParameters());
                            }

                            if (log.isDebugEnabled()) {
                                log.debug("SETTINGRELAY redirect URL : " + requestedURI);
                            }

                            response.sendRedirect(requestedURI);
                            return;
                        } else {
                            // default value
                            String redirectUrl = ssoSPConfigProperties.getProperty
                                    (WebappSSOConstants.APP_SERVER_URL) + request.getContextPath();

                            String tenantName = request.getContext().findParameter(MultiTenantSSOUtils
                                    .ENABLE_SAML2_SSO_WITH_TENANT);

                            // If a custom redirect domain is present in request
                            if (!StringUtils.isBlank(tenantName) && tenantDomainMap.containsKey(tenantName)) {

                                String tenantDomain = tenantDomainMap.get(tenantName);

                                String tenantURIComponent = "/t/" + tenantName + "/webapps";

                                redirectUrl = "https://" + tenantDomain + request.getRequestURI()
                                            .replace(tenantURIComponent, "");

                                Cookie sessionCookie = new Cookie(MultiTenantSSOUtils.SESSION_COOKIE_NAME,
                                        request.getSession().getId());
                                sessionCookie.setDomain(tenantDomain);
                                sessionCookie.setPath("/");
                                sessionCookie.setSecure(true);

                                if (log.isDebugEnabled()) {
                                    log.debug("Setting session cookie for custom redirect domain : " +
                                            tenantDomainMap.get(tenantName));
                                }
                                response.addCookie(sessionCookie);
                            }


                            //todo remove
//                            redirectUrl = ssoSPConfigProperties.getProperty(WebappSSOConstants.APP_SERVER_URL) +
//                                    request.getContextPath();
                            if (log.isDebugEnabled()) {
                                log.debug("SETTING redirect URL : " + redirectUrl);
                            }

                            response.sendRedirect(redirectUrl);
                            return;
                        }
                    }
                    //Handling redirect from acs page after SLO response. This will be done if
                    // WWebappSSOConstants.HANDLE_CONSUMER_URL_AFTER_SLO is defined
                    // WebappSSOConstants.REDIRECT_PATH_AFTER_SLO value is used determine the redirect path
                    else if (request.getRequestURI().endsWith(
                            ssoSPConfigProperties.getProperty(WebappSSOConstants.CONSUMER_URL_POSTFIX)) &&
                            Boolean.parseBoolean(ssoSPConfigProperties.getProperty(
                                    WebappSSOConstants.HANDLE_CONSUMER_URL_AFTER_SLO))) {
                        response.sendRedirect(redirectPath);
                        return;
                    }
                } catch (SSOAgentException e) {
                    handleException(request, e);
                }

            } else if (resolver.isSLOURL()) {

                if (log.isDebugEnabled()) {
                    log.debug("Processing Single Log Out URL");
                }
                samlSSOManager = new SAML2SSOManager(ssoAgentConfig);
                if (resolver.isHttpPostBinding()) {
                    if (request.getSession(false).getAttribute(SSOAgentConstants.SESSION_BEAN_NAME) != null) {
                        ssoAgentConfig.getSAML2().setPassiveAuthn(false);
                        String htmlPayload = samlSSOManager.buildPostRequest(request, response, true);
                        response.addHeader(HttpHeaders.CONTENT_TYPE, MEDIA_TYPE_TEXT_HTML);
                        SSOAgentUtils.sendPostResponse(request, response, htmlPayload);
                    } else {
                        log.warn("Attempt to logout from a already logout session.");
                        response.sendRedirect(request.getContext().getPath());
                        return;
                    }
                } else {
                    //if "SSOAgentConstants.HTTP_BINDING_PARAM" is not defined, default to redirect
                    ssoAgentConfig.getSAML2().setPassiveAuthn(false);
                    response.sendRedirect(samlSSOManager.buildRedirectRequest(request, true));
                }
                return;

            } else if (resolver.isSAML2SSOURL() ||
                    (ssoAgentConfig.isSAML2SSOLoginEnabled() && (request.getSession(false) == null ||
                            request.getSession(false).getAttribute(SSOAgentConstants.SESSION_BEAN_NAME) == null))) {
                //handling the unauthenticated requests for all contexts.
                if (log.isDebugEnabled()) {
                    log.debug("Processing SSO URL");
                }
                samlSSOManager = new SAML2SSOManager(ssoAgentConfig);
                String relayStateId = SSOAgentUtils.createID();

                RelayState relayState = new RelayState();

//                String redirectDomain = request.getHeader(ssoSPConfigProperties.getProperty(MultiTenantSSOUtils
//                        .CUSTOM_REDIRECT_DOMAIN));

//                if (!StringUtils.isBlank(redirectDomain)) {
//                    relayState.setRequestedURL();
//                }
                relayState.setRequestedURL(request.getRequestURI());

                relayState.setRequestQueryString(request.getQueryString());
                relayState.setRequestParameters(request.getParameterMap());

                ssoAgentConfig.getSAML2().setRelayState(relayStateId);
                request.getSession(Boolean.FALSE).setAttribute(relayStateId, relayState);

                if (resolver.isHttpPostBinding()) {
                    ssoAgentConfig.getSAML2().setPassiveAuthn(false);
                    String htmlPayload = samlSSOManager.buildPostRequest(request, response, false);
                    response.addHeader(HttpHeaders.CONTENT_TYPE, MEDIA_TYPE_TEXT_HTML);
                    SSOAgentUtils.sendPostResponse(request, response, htmlPayload);
                    return;

                } else {
                    ssoAgentConfig.getSAML2().setPassiveAuthn(false);
                    response.sendRedirect(samlSSOManager.buildRedirectRequest(request, false));
                }
                return;

            }
            if (request.getSession(false) != null) {
                LoggedInSessionBean loggedInSessionBean = (LoggedInSessionBean)
                        request.getSession(false).getAttribute(SSOAgentConstants.SESSION_BEAN_NAME);

                if (loggedInSessionBean != null) {

                    LoggedInSessionBean.SAML2SSO sessionBean = loggedInSessionBean.getSAML2SSO();
                    String principalName = sessionBean.getSubjectId();

                    //Setting user name and roles in to UserPrincipal
                    if (principalName != null) {
                        List<String> rolesList = null;
                        Map<String, String> attrMap = sessionBean.getSubjectAttributes();

                        if (attrMap != null && !attrMap.isEmpty()) {
                            String roles = attrMap.get("http://wso2.org/claims/role");

                            if (roles != null && !roles.isEmpty()) {
                                String[] rolesArr = roles.split(",");
                                rolesList = Arrays.asList(rolesArr);
                            }
                        }
                        request.setUserPrincipal(new GenericPrincipal(principalName, null, rolesList));
                    }
                }
            }

        } catch (SSOAgentException e) {
            log.error("An error has occurred", e);
            throw e;
        }

        if (log.isDebugEnabled()) {
            log.debug("End of SAMLSSOValve invoke.");
        }

        getNext().invoke(request, response);
    }

    public void backgroundProcess() {
        super.backgroundProcess();
    }

    protected void handleException(HttpServletRequest request, SSOAgentException e)
            throws SSOAgentException {
        if (request.getSession(false) != null) {
            request.getSession(false).removeAttribute(SSOAgentConstants.SESSION_BEAN_NAME);
        }
        throw e;
    }

    /**
     * This method reads the Redirect Path After SLO. If the redirect path is read from session then it is removed.
     * Priority of reading the redirect path is 1. Session, 2. Context 3. Config
     * @param request
     * @return redirect path relative to the current application path
     */
    private String readAndForgetRedirectPathAfterSLO(Request request) {
        String redirectPath = null;
        if (request.getSession(false) != null) {
            redirectPath = (String) request.getSession(false).getAttribute(WebappSSOConstants.REDIRECT_PATH_AFTER_SLO);
            request.getSession(false).removeAttribute(WebappSSOConstants.REDIRECT_PATH_AFTER_SLO);
        }
        if (redirectPath == null) {
            redirectPath = (String) request.getContext().findParameter(WebappSSOConstants.REDIRECT_PATH_AFTER_SLO);
        }
        if (redirectPath == null) {
            redirectPath = ssoSPConfigProperties.getProperty(WebappSSOConstants.REDIRECT_PATH_AFTER_SLO);
        }

        if (redirectPath != null && !redirectPath.isEmpty()) {
            redirectPath = request.getContext().getPath().concat(redirectPath);
        } else {
            redirectPath = request.getContext().getPath();
        }

        if (log.isDebugEnabled()) {
            log.debug("Redirect path = " + redirectPath);
        }

        return redirectPath;
    }

    /**
     * In case the redirect domain is different from the application server domain, we are caching it here against the
     * tenant name.
     * @param request containing the webapp context information.
     */
    private void cacheRedirectDomain(Request request) {

        String tenantName = request.getContext().findParameter(MultiTenantSSOUtils.ENABLE_SAML2_SSO_WITH_TENANT);

        if (!StringUtils.isBlank(tenantName) && !tenantDomainMap.containsKey(tenantName)) {
            String redirectDomain = request.getHeader(ssoSPConfigProperties.getProperty(MultiTenantSSOUtils
                    .CUSTOM_REDIRECT_DOMAIN));

            if (!StringUtils.isBlank(redirectDomain)) {
                if (log.isDebugEnabled()) {
                    log.debug("Caching redirect domain : " + redirectDomain + " for tenant " + tenantName);
                }
                tenantDomainMap.put(tenantName, redirectDomain);
            }
        }
    }
}
