/*
 * Copyright © 2020-2025 ForgeRock AS (obst@forgerock.com)
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
package com.forgerock.sapi.gateway.jws;

import java.security.SignatureException;

import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.SignedJwt;

/**
 * Validator which validates the signature of a JWT by using a JWK in the supplied JWKSet
 */
public interface JwtSignatureValidator {

    /**
     * Validates the signature of the jwt, the method will return without throwing an exception if successful
     *
     * @param jwt    SignedJwt to validate the signature of
     * @param jwkSet JWKSet containing a JWK to use for the validation (typically the JWK to use will be determined by the kid JWT header)
     * @throws SignatureException if validation is unsuccessful, this may be due to the signature not matching the expected
     *                            signature, or some other issue with the supplied jwt or jwkSet
     */
    void validateSignature(SignedJwt jwt, JWKSet jwkSet) throws SignatureException;

}
