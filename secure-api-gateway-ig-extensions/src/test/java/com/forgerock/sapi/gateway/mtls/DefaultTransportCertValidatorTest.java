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

import static com.forgerock.sapi.gateway.mtls.DefaultTransportCertValidator.Heaplet.CONFIG_TRANSPORT_KEY_USE;
import static com.forgerock.sapi.gateway.util.CryptoUtils.generateExpiredX509Cert;
import static com.forgerock.sapi.gateway.util.CryptoUtils.generateRsaKeyPair;
import static com.forgerock.sapi.gateway.util.CryptoUtils.generateX509Cert;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.secrets.Purpose.purpose;
import static org.forgerock.secrets.jwkset.JwkSetSecretStore.JwkPredicates.keyUse;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.stream.Stream;

import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.secrets.jwkset.JwkSetSecretStore;
import org.forgerock.secrets.keys.CertificateVerificationKey;
import org.forgerock.util.Options;
import org.forgerock.util.Pair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.forgerock.sapi.gateway.mtls.DefaultTransportCertValidator.Heaplet;
import com.forgerock.sapi.gateway.util.CryptoUtils;

class DefaultTransportCertValidatorTest {

    // TEST_TLS_CERT actual X509 certificate
    private static X509Certificate TEST_TLS_CERT;
    // JWKSet containing TEST_TLS_CERT plus others.
    private static JWKSet TEST_JWKS;
    // The transport key use that we use to define the purpose
    private static final String TLS_KEY_USE = "tls";
    // It's easier to use a real JwkSetSecretStore
    private static JwkSetSecretStore jwkSetSecretStore;

    @BeforeAll
    public static void beforeAll() throws Exception {
        final Pair<X509Certificate, JWKSet> transportCertPemAndJwkSet =
                CryptoUtils.generateTestTransportCertAndJwks(TLS_KEY_USE);
        TEST_TLS_CERT = transportCertPemAndJwkSet.getFirst();
        TEST_JWKS = transportCertPemAndJwkSet.getSecond();
    }

    @Test
    void shouldFindValidCertWithTlsKeyUsePredicate() {
        // Given - JwkSetSecretStore with predicate for TLS purpose, requiring keyUse TLS
        jwkSetSecretStore = new JwkSetSecretStore(TEST_JWKS, Options.defaultOptions())
                .withPurposePredicate(purpose(TLS_KEY_USE, CertificateVerificationKey.class), keyUse(TLS_KEY_USE));
        // ... and - validator using purpose TLS
        DefaultTransportCertValidator transportCertValidator = new DefaultTransportCertValidator(TLS_KEY_USE);
        // When/Then - cert found
        assertThatNoException()
                .isThrownBy(() -> transportCertValidator.validate(TEST_TLS_CERT, jwkSetSecretStore)
                                                        .getOrThrowIfInterrupted());
    }

    private static Stream<DefaultTransportCertValidator> defaultTransportCertValidator() {
        return Stream.of(
                // 'transportCertKeyUse' config - validator configured to use TLS as expected transport cert purpose
                new DefaultTransportCertValidator(),
                // No 'transportCertKeyUse' config - validator configured to allow any transport cert purpose
                new DefaultTransportCertValidator(TLS_KEY_USE)
        );
    }

    @ParameterizedTest
    @MethodSource("defaultTransportCertValidator")
    void shouldFindValidCertWhenNoPurposeKeyUsePredicate(final DefaultTransportCertValidator validator) {
        // Given - JwkSetSecretStore not constraining any Purpose (with a predicate)
        jwkSetSecretStore = new JwkSetSecretStore(TEST_JWKS, Options.defaultOptions());
        // When/Then - cert found
        assertThatNoException()
                .isThrownBy(() -> validator.validate(TEST_TLS_CERT, jwkSetSecretStore).getOrThrowIfInterrupted());
    }

    @Test
    void shouldFailToFindCertWhenKeyUseNotAsExpected() {
        // Given - JwkSetSecretStore with predicate for "sig" purpose, requiring keyUse "sig"
        jwkSetSecretStore = new JwkSetSecretStore(TEST_JWKS, Options.defaultOptions())
                .withPurposePredicate(purpose("sig", CertificateVerificationKey.class), keyUse("sig"));
        // ... and - validator using purpose "sig" (so requires JWK keyUse to be "sig")
        DefaultTransportCertValidator validator = new DefaultTransportCertValidator("sig");
        // When/Then - cert matches, but its JWK keyUse is TLS, so validation fails
        assertThatThrownBy(() -> validator.validate(TEST_TLS_CERT, jwkSetSecretStore).getOrThrowIfInterrupted())
                .isInstanceOf(CertificateException.class)
                .hasMessage("Failed to find JWK entry in provided JWKSet which matches the X509 cert");
    }

    @Test
    void shouldFailWhenCertNotInJwks() {
        // Given - JwkSetSecretStore with predicate for TLS purpose, requiring keyUse TLS
        jwkSetSecretStore = new JwkSetSecretStore(TEST_JWKS, Options.defaultOptions())
                .withPurposePredicate(purpose(TLS_KEY_USE, CertificateVerificationKey.class), keyUse(TLS_KEY_USE));
        DefaultTransportCertValidator validator = new DefaultTransportCertValidator(TLS_KEY_USE);
        // When - non-existent (new) cert is tested,
        X509Certificate certNotInJwks = generateX509Cert(generateRsaKeyPair(), "CN=test");
        // Then - validation fails
        assertThatThrownBy(() -> validator.validate(certNotInJwks, jwkSetSecretStore)
                                           .getOrThrowIfInterrupted())
                .isInstanceOf(CertificateException.class)
                .hasMessage("Failed to find JWK entry in provided JWKSet which matches the X509 cert");
    }

    @Test
    void shouldFailWhenCertIsExpired() {
        // Given - JwkSetSecretStore with predicate for TLS purpose, requiring keyUse TLS
        jwkSetSecretStore = new JwkSetSecretStore(TEST_JWKS, Options.defaultOptions())
                .withPurposePredicate(purpose(TLS_KEY_USE, CertificateVerificationKey.class), keyUse(TLS_KEY_USE));
        DefaultTransportCertValidator validator = new DefaultTransportCertValidator(TLS_KEY_USE);
        // When - expired cert is tested,
        X509Certificate expiredCert = generateExpiredX509Cert(generateRsaKeyPair(), "CN=abc");
        // Then - validation should fail
        assertThatThrownBy(() -> validator.validate(expiredCert, jwkSetSecretStore)
                                          .getOrThrowIfInterrupted())
                .isInstanceOf(CertificateException.class)
                .hasMessageContaining("certificate expired on");
    }

    @Test
    void shouldFailWhenBeforeCertStartDate() {
        // Given - JwkSetSecretStore with predicate for TLS purpose, requiring keyUse TLS
        jwkSetSecretStore = new JwkSetSecretStore(TEST_JWKS, Options.defaultOptions())
                .withPurposePredicate(purpose(TLS_KEY_USE, CertificateVerificationKey.class), keyUse(TLS_KEY_USE));
        DefaultTransportCertValidator validator = new DefaultTransportCertValidator(TLS_KEY_USE);
        // ... and cert with date prior to start date
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DAY_OF_YEAR, 5);
        Date certStartDate = calendar.getTime();
        calendar.add(Calendar.DAY_OF_YEAR, 50);
        Date certEndDate = calendar.getTime();
        X509Certificate certStartDateNotReached = generateX509Cert(generateRsaKeyPair(),
                                                                   "CN=abc",
                                                                   certStartDate,
                                                                   certEndDate);
        // Then - validation should fail
        assertThatThrownBy(() -> validator.validate(certStartDateNotReached, jwkSetSecretStore)
                                          .getOrThrowIfInterrupted())
                .isInstanceOf(CertificateException.class)
                .hasMessageContaining("certificate not valid till");
    }

    private static Stream<JsonValue> validatorConfig() {
        return Stream.of(
                // Minimal config
                json(object()),
                // 'transportCertKeyUse' config
                json(object(field(CONFIG_TRANSPORT_KEY_USE, "tls")))
        );
    }

    @ParameterizedTest
    @MethodSource("validatorConfig")
    void shouldSuccessfullyCreateByHeaplet(final JsonValue validatorConfig) throws Exception {
         Heaplet heaplet = new DefaultTransportCertValidator.Heaplet();
         assertThat(heaplet.create(Name.of("validator"), validatorConfig, new HeapImpl(Name.of("heap"))))
                 .isNotNull();
    }
}