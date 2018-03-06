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

import org.apache.catalina.connector.Request;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.webapp.mgt.sso.WebappSSOConstants;

import java.util.Properties;

/**
 *
 */
public class MultiTenantSSOUtils {

    static final String ENABLE_SAML2_SSO_WITH_TENANT = "enable.saml2.sso.with.tenant";
    static final String SKIP_URIS = "sso.skip.uris";

    static final String CUSTOM_ACS_HEADER = "CustomACSHeader";
    static final String CUSTOM_REDIRECT_DOMAIN = "CustomRedirectDomainHeader";

    static final String TENANT_URL_PREFIX = "/t/";
    static final String WEBAPP_PREFIX = "/webapps";

    public static String generateConsumerUrl(Request request, Properties ssoSPConfigProperties) {

        String assertionConsumerURL = request.getHeader(ssoSPConfigProperties.getProperty(CUSTOM_ACS_HEADER));

        if (StringUtils.isBlank(assertionConsumerURL)) {
            assertionConsumerURL = ssoSPConfigProperties.getProperty(WebappSSOConstants.APP_SERVER_URL) + request.getContextPath() +
                    ssoSPConfigProperties.getProperty(WebappSSOConstants.CONSUMER_URL_POSTFIX);
        }

        return assertionConsumerURL;
    }
}
