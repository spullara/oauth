/*
 * Copyright 2007 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.oauth;

import java.util.HashMap;
import java.util.Map;

/**
 * Describes an OAuth-related problem, using a set of named parameters. One
 * parameter identifies the basic problem, and the others provide supplementary
 * diagnostic information. This can be used to capture information from a
 * response that conforms to the OAuth <a
 * href="http://wiki.oauth.net/ProblemReporting">Problem Reporting extension</a>.
 * 
 * @author John Kristian
 */
public class OAuthProblemException extends Exception {

    public static final String OAUTH_PROBLEM = "oauth_problem";

    public static final String HTTP_STATUS_CODE = "HTTP status";

    public OAuthProblemException() {
    }

    public OAuthProblemException(String problem) {
        super(problem);
        if (problem != null) {
            parameters.put(OAUTH_PROBLEM, problem);
        }
    }

    private final Map<String, Object> parameters = new HashMap<String, Object>();

    public void setParameter(String name, Object value) {
        getParameters().put(name, value);
    }

    public Map<String, Object> getParameters() {
        return parameters;
    }

    public String getProblem() {
        return (String) getParameters().get(OAUTH_PROBLEM);
    }

    public int getHttpStatusCode() {
        Object code = getParameters().get(HTTP_STATUS_CODE);
        if (code == null) {
            return 200;
        } else if (code instanceof Number) { // the usual case
            return ((Number) code).intValue();
        } else {
            return Integer.parseInt(code.toString());
        }
    }

    private static final long serialVersionUID = 1L;

}
