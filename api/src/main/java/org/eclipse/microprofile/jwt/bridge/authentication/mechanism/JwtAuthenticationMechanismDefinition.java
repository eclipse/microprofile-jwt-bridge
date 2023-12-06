/*
 * Copyright (c) 2023-2024 Contributors to the Eclipse Foundation
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
package org.eclipse.microprofile.jwt.bridge.authentication.mechanism;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 * Annotation used to define a JWT authentication mechanism
 */
@Target({TYPE, METHOD})
@Retention(RUNTIME)
public @interface JwtAuthenticationMechanismDefinition {

    /**
     * Required, unless {@link #publicKeyLocation()} is specified.
     *
     * @return Public verification key in the Base64 encoded format
     */
    String publicKey() default "";
    /**
     * Required, unless {@link #publicKey()} is specified.
     *
     * @return Location of the public verification key
     */
    String publicKeyLocation() default "";

    /**
     * @return public key algorithms that can be used to verify the token signature. "RS256" or "ES256" algorithms must
     *         be supported.
     */
    String[] publicKeyAlgorithm() default {"RS256"};

    /**
     * @return Location of the private or secret decryption key
     */
    String decryptKeyLocation() default "";

    /**
     * @return decryption key algorithms that can be used to decrypt the token. "RSA-OAEP-256" or "RSA-OAEP" algorithms
     *         must be supported.
     */
    String[] decryptKeyAlgorithm() default {"RSA-OAEP-256"};

    /**
     * Required
     *
     * @return Token issuer
     */
    String issuer();

    /**
     * Recommended
     *
     * @return Token audiences
     */
    String[] audiences() default {};

    /**
     * @return name of the HTTP header which is expected to provide JWT tokens
     */
    String header() default "Authorization";

    /**
     * Name of the cookie which is expected to contain JWT token. This property will only be checked if
     * {@link #header()} is set to 'Cookie'.
     *
     * @return Name of the cookie which is expected to contain JWT token.
     */
    String cookieName() default "Bearer";

    /**
     * Recommended
     *
     * @return Token age
     */
    long tokenAge() default -1;

    /**
     * Recommended
     *
     * @return Clock skew
     */
    long clockSkew() default -1;

}
