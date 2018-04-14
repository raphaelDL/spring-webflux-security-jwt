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
package io.rapha.spring.reactive.security;

import io.rapha.spring.reactive.security.auth.JWTReactiveAuthenticationManager;
import io.rapha.spring.reactive.security.auth.ServerHttpBearerAuthenticationConverter;
import io.rapha.spring.reactive.security.auth.WebFilterChainServerJWTAuthenticationSuccessHandler;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;

/**
 * A Spring RESTful Application showing authentication and authorization
 *
 * @author rafa
 */
@SpringBootApplication
@EnableWebFluxSecurity
public class SecuredRestApplication {

    @Value("${DEFAULT_SECRET}")
    private String secret;

    @Value("${jwt.expiration_time}")
    private long expirationTime;

    @Value("${ISSUER}")
    private String issuer;

    /**
     * Main entry point, built on top of Spring Boot it will point the begin of
     * execution.
     *
     * @param args Regular command line arguments can be added and their treatment
     *             may be required
     */
    public static void main(String[] args) {
        SpringApplication.run(SecuredRestApplication.class, args);
    }

    /**
     * A custom UserDetailsService to provide quick user rights for Spring Security,
     * more formal implementations may be added as separated files and annotated as
     * a Spring stereotype.
     *
     * @return MapReactiveUserDetailsService an InMemory implementation of user details
     */
    @Bean
    public MapReactiveUserDetailsService userDetailsRepository() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("user")
                .roles("USER", "ADMIN")
                .build();
        return new MapReactiveUserDetailsService(user);
    }

    /**
     * For Spring Security webflux, a chain of filters will provide user authentication
     * and authorization, we add custom filters to enable JWT token approach.
     *
     * @param http An initial object to build common filter scenarios.
     *             Customized filters are added here.
     * @return SecurityWebFilterChain A filter chain for web exchanges that will
     * provide security
     */
    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        AuthenticationWebFilter authenticationJWT =
                new AuthenticationWebFilter(new UserDetailsRepositoryReactiveAuthenticationManager(userDetailsRepository()));
        authenticationJWT.setRequiresAuthenticationMatcher(ServerWebExchangeMatchers.pathMatchers("/login"));
        authenticationJWT.setAuthenticationSuccessHandler(serverAuthenticationSuccessHandler());

        return http
                .addFilterAt(authenticationJWT, SecurityWebFiltersOrder.FIRST)
                .addFilterAt(authenticationWebFilter(), SecurityWebFiltersOrder.HTTP_BASIC)
                .authorizeExchange()
                    .pathMatchers("/login")
                        .authenticated()
                .and()
                    .authorizeExchange()
                        .pathMatchers("/api/**")
                            .authenticated()
                .and()
                    .authorizeExchange()
                        .anyExchange()
                            .denyAll()
                .and()
                .build();
    }

    @Bean
    public AuthenticationWebFilter authenticationWebFilter() {
        AuthenticationWebFilter webFilter = new AuthenticationWebFilter(reactiveAuthenticationManager());
        webFilter.setRequiresAuthenticationMatcher(ServerWebExchangeMatchers.pathMatchers("/api/**"));
        webFilter.setAuthenticationConverter(new ServerHttpBearerAuthenticationConverter(secret));
        return webFilter;
    }

    @Bean
    public ReactiveAuthenticationManager reactiveAuthenticationManager() {
        return new JWTReactiveAuthenticationManager();
    }

    @Bean
    public ServerAuthenticationSuccessHandler serverAuthenticationSuccessHandler() {
        return new WebFilterChainServerJWTAuthenticationSuccessHandler(secret, expirationTime, issuer);
    }
}
