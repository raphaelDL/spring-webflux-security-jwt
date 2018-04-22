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
package io.rapha.spring.reactive.security.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.function.Function;

/**
 * This converter extracts a bearer token from a WebExchange and
 * returns an Authentication object if the JWT token is valid.
 * Validity means is well formed and signature is correct
 */
public class ServerHttpBearerAuthenticationConverter implements Function<ServerWebExchange, Mono<Authentication>> {

    private static final String BEARER = "Bearer ";

    private String secret;

    @Autowired
    public ServerHttpBearerAuthenticationConverter(String secret) {
        this.secret = secret;
    }

    /**
     * Apply this function to the current WebExchange, an Authentication object
     * is returned when completed.
     *
     * @param serverWebExchange
     * @return
     */
    @Override
    public Mono<Authentication> apply(ServerWebExchange serverWebExchange) {
        Mono<Authentication> result = Mono.empty();
        String jwtPayload = extractJwtPayload(serverWebExchange);
        if (jwtPayload.length() > BEARER.length()) {
            String token = jwtPayload.substring(BEARER.length(), jwtPayload.length());
            try {
                String subject = getJwtVerifier().verify(token).getSubject();
                result = Mono.just(new UsernamePasswordAuthenticationToken(subject, null, new ArrayList<>()));
            } catch (JWTVerificationException e) {
                result = Mono.empty();
            }
        }
        return result;
    }

    private String extractJwtPayload(ServerWebExchange exchange) {
        String header = exchange
                .getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);

        return header != null
                ? header
                : "";
    }

    public JWTVerifier getJwtVerifier() {
        JWTVerifier verifier = null;

        try {
            verifier = JWT.require(Algorithm.HMAC512(secret)).build();
        } catch (UnsupportedEncodingException ignored) {
            // never happens
        }

        return verifier;
    }
}
