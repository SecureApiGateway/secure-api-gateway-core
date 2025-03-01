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
package com.forgerock.sapi.gateway.jwks.cache.caffeine;

import java.net.URI;

import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.openig.fapi.jwks.JwkSetService;

import com.forgerock.sapi.gateway.jwks.cache.CachingJwkSetService;

/**
 * Implementation of {@link CachingJwkSetService} which uses a {@link CaffeineCache} as its cache implementation.
 * This class is required in order to be able to create an instance via IG config.
 */
public class CaffeineCachingJwkSetService extends CachingJwkSetService {
    public CaffeineCachingJwkSetService(JwkSetService underlyingStore, CaffeineCache<URI, JWKSet> jwkSetCache) {
        super(underlyingStore, jwkSetCache);
    }
}
