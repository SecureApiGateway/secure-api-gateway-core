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
package com.forgerock.sapi.gateway.mtls;

import static org.forgerock.openig.util.JsonValues.optional;
import static org.forgerock.secrets.Purpose.VERIFY_CERTIFICATE;
import static org.forgerock.secrets.Purpose.purpose;
import static org.forgerock.util.promise.NeverThrowsException.neverThrown;
import static org.forgerock.util.promise.Promises.newExceptionPromise;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import org.forgerock.json.JsonValue;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.secrets.Purpose;
import org.forgerock.secrets.SecretConstraint;
import org.forgerock.secrets.jwkset.JwkSetSecretStore;
import org.forgerock.secrets.keys.CertificateVerificationKey;
import org.forgerock.secrets.keys.CryptoKey;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Certificate validation is achieved by comparing the incoming {@link X509Certificate client certificate} with
 * those obtained from the client {@link JwkSetSecretStore JWKSet}. That is, we obtain valid certificates for the
 * expected {@code validKeyUse} from the JWKSet and compare the client certificate with these certificates to find
 * match.
 * <p>
 * If no {@code validKeyUse} is supplied, then the default {@link Purpose#VERIFY_CERTIFICATE "verifyCertificate"} label
 * is used. For the Open Banking use case, the {@code JWK.use} value is expected to be
 * {@value org.forgerock.json.jose.jwk.KeyUseConstants#TLS} for a cert that is used for MTLS purposes. This is a custom
 * key use defined by Open Banking.
 */
public class DefaultTransportCertValidator implements TransportCertValidator {

    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultTransportCertValidator.class);

    /**
     * Optionally validate that the JWK entry has a "use" value that matches this value.
     *
     * If this is configured as null, then checking of the "use" value will be skipped.
     */
    private final String transportCertKeyUse;

    public DefaultTransportCertValidator() {
        this(VERIFY_CERTIFICATE.getLabel());
    }

    public DefaultTransportCertValidator(String transportCertKeyUse) {
        this.transportCertKeyUse = transportCertKeyUse;
    }

    public Promise<Void, CertificateException> validate(X509Certificate clientCertificate,
                                                        JwkSetSecretStore jwkSetSecretStore) {
        Reject.ifNull(clientCertificate, "certificate must be supplied");
        Reject.ifNull(jwkSetSecretStore, "jwkSetSecretStore must be supplied");
        try {
            clientCertificate.checkValidity();
        } catch (CertificateException certException) {
            return newExceptionPromise(certException);
        }
        Purpose<CertificateVerificationKey> tlsPurpose =
                purpose(transportCertKeyUse, CertificateVerificationKey.class)
                        .withConstraints(matchesX509Cert(clientCertificate));
        return jwkSetSecretStore.getValid(tlsPurpose)
                .then(this::keysPresentInRegisteredCerts, neverThrown());
    }

    private static SecretConstraint<CryptoKey> matchesX509Cert(final X509Certificate tlsClientCert) {
        // Note that this emulates the real way in which an X.509 cert will be validated via a JwkSetSecretStore
        return secret -> {
            try {
                tlsClientCert.checkValidity();
            } catch (CertificateExpiredException | CertificateNotYetValidException certificateException) {
                LOGGER.trace("Client certificate is not valid {}", certificateException.getMessage());
                return false;
            }
            return secret.getCertificate(X509Certificate.class)
                         .filter(x509Cert -> {
                             try {
                                 boolean tf = Arrays.equals(x509Cert.getEncoded(), tlsClientCert.getEncoded());
                                 return tf;
                             } catch (CertificateEncodingException certificateException) {
                                 LOGGER.trace("Certificate encoding error {}", certificateException.getMessage());
                                 return false;
                             }
                         })
                         .isPresent();
        };
    }

    private Void keysPresentInRegisteredCerts(
            final Stream<CertificateVerificationKey> keys)
            throws CertificateException {
        List<CertificateVerificationKey> keysList = keys.toList();
        if (keysList.isEmpty()) {
            throw new CertificateException("Failed to find JWK entry in provided JWKSet which matches the X509 cert");
        }
        LOGGER.debug("Found {} registered certificates matching request {} certificate", keysList.size(),
                     transportCertKeyUse);
        return null;
    }

    /**
     * Heaplet responsible for creating {@link DefaultTransportCertValidator} objects
     * <pre>
     * {@code {
     *      "type": "DefaultTransportCertValidator",
     *      "config": {
     *          "transportCertKeyUse" : expression<string>  [OPTIONAL - The expected key usage to use to retrieve and
     *                                                                  validate the transport cert (1). Defaults to
     *                                                                  the generic "verifyCertificate" key usage (2).]
     *      }
     *   }
     * }
     * }
     * </pre>
     * <p>
     * Notes:
     * <ol>
     *     <li>
     *         Config 'transportCertKeyUse' should align with the {@code CachingJwkSetService#transportCertKeyUse}
     *         config to successfully identify the transport cert, as that config restricts which JWKs are available,
     *         by key use, to prevent cross-JWK usage.
     *      </li>
     *      <li>
     *         See {@link Purpose#VERIFY_CERTIFICATE} for default secret label if no key use is supplied, which is the
     *         general purpose {@link Purpose} to obtain certificates. For the Open Banking use case, the
     *         {@code JWK.use} value is expected to be {@value org.forgerock.json.jose.jwk.KeyUseConstants#TLS} for a
     *         cert that is used for MTLS purposes. This is a custom key use defined by Open Banking.
     *     </li>
     *     </li>
     * </ol>
     * <p>
     * Example config:
     * <pre>
     * {
     *       "name": "OBTransportCertValidator",
     *       "type": "TransportCertValidator",
     *       "config": {
     *         "transportCertKeyUse": "tls"
     *       }
     * }
     * </pre>
     */
    public static class Heaplet extends GenericHeaplet {

        // This key 'use' should align with the CachingJwkSetService.transportCertKeyUse to match expected JWK use
        static final String CONFIG_TRANSPORT_KEY_USE = "transportCertKeyUse";
        static final String CONFIG_OLD_TRANSPORT_KEY_USE = "validKeyUse";
        static final String DEFAULT_TRANSPORT_KEY_USE = VERIFY_CERTIFICATE.getLabel();

        @Override
        public Object create() throws HeapException {
            String transportCertKeyUse =
                    config.get(CONFIG_TRANSPORT_KEY_USE)
                          .as(optional())
                          .map(JsonValue::asString)
                          .orElseGet(() -> config.get("validKeyUse")
                                                 // Check for old 'validKeyUse' - and warn of config name change
                                                 .as(evaluatedWithHeapProperties())
                                                 .as(json -> {
                                                     if (json.isNotNull()) {
                                                         LOGGER.warn("Config '{}' is deprecated, please use '{}'",
                                                                     CONFIG_OLD_TRANSPORT_KEY_USE,
                                                                     CONFIG_TRANSPORT_KEY_USE);
                                                     }
                                                     return json;
                                                 })
                                                 .defaultTo(DEFAULT_TRANSPORT_KEY_USE)
                                                 .asString());
            return new DefaultTransportCertValidator(transportCertKeyUse);
        }
    }
}
