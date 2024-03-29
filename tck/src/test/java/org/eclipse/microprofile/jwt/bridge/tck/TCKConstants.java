/*
 * Copyright (c) 2016-2024 Contributors to the Eclipse Foundation
 *
 *  See the NOTICE file(s) distributed with this work for additional
 *  information regarding copyright ownership.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  You may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package org.eclipse.microprofile.jwt.bridge.tck;

public class TCKConstants {
    // TestNG groups
    public static final String TEST_GROUP_UTILS = "utils";
    public static final String TEST_GROUP_UTILS_EXTRA = "utils-extra";
    public static final String TEST_GROUP_JAXRS = "jaxrs";
    public static final String TEST_GROUP_EJB = "ejb-optional";
    public static final String TEST_GROUP_SERVLET = "servlet-optional";
    public static final String TEST_GROUP_EE_SECURITY = "ee-security-optional";
    public static final String TEST_GROUP_JACC = "jacc-optional";
    // The expected JWT iss value
    public static final String TEST_ISSUER = "https://server.example.com";

    private TCKConstants() {
    }
}
