/*
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package io.rapha.spring.reactive.security.auth.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.time.Instant;

/**
 * Decides when a JWT string is valid.
 * First  try to parse it, then check that
 * the signature is correct.
 * If something fails an empty Mono is returning
 * meaning that is not valid.
 * Verify that expiration date is valid
 */
public class JWTCustomVerifier {
    public static Mono<SignedJWT> check(String token) {
        SignedJWT signedJWT;
        JWSVerifier jwsVerifier;
        Instant expirationDate;

        boolean status;

        try {
            jwsVerifier = new MACVerifier(JWTSecrets.DEFAULT_SECRET);
        } catch (JOSEException e) {
            return Mono.empty();
        }

        try {
            signedJWT = SignedJWT.parse(token);
            expirationDate = signedJWT.getJWTClaimsSet()
                    .getExpirationTime()
                    .toInstant();

        } catch (ParseException e) {
            return Mono.empty();
        }

        try {
            status = signedJWT.verify(jwsVerifier);

        } catch (JOSEException e) {
            return Mono.empty();
        }

        return status &&  isNotExpired(expirationDate) ? Mono.just(signedJWT) : Mono.empty();
    }

    private static boolean isNotExpired(Instant expirationDate) {
        return expirationDate.isAfter(Instant.now());
    }
}
