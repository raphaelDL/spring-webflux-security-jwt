# Authentication and Authorization using JWT with Spring WebFlux and Spring Security Reactive

### Nice Docs to Read First

Before getting started I suggest you go through the next reference 

[Spring Webflux](https://docs.spring.io/spring/docs/5.1.0.RELEASE/spring-framework-reference/web-reactive.html#spring-webflux)

[Spring Security Reactive](https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#reactive-applications)

[Spring Security Architecture](https://spring.io/guides/topicals/spring-security-architecture)

### Enable Spring WebFlux Security
First enable Webflux Security in your application  with `@EnableWebFluxSecurity`

```java
@SpringBootApplication
@EnableWebFluxSecurity
public class SecuredRestApplication {
....
}
```

### Create an InMemory UserDetailsService

Define a custom `UserDetailsService` bean where an User with password and
initial roles is added:


```java
@Bean
    public MapReactiveUserDetailsService userDetailsRepository() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("user")
                .roles("USER", "ADMIN")
                .build();
        return new MapReactiveUserDetailsService(user);
    }
```

In this example user information will be stored in memory using a `Map` but it can be replaced by different strategies.

Before getting a Json Web Token an user should use another authentication mechanism, for example HTTP Basic Authentication and provided the right credentials a JWT will be issued which can be used to perform future API calls by changing the `Authetication` method from Basic to Bearer.


### Starting from Basic Authentication

Below there's a simple way to define Basic Authentication with Spring Security. Customization is needed in order to return a JWT on succesful authentication.

```java
@Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
            .authorizeExchange()
                .anyExchange().authenticated()
                .and()
            .httpBasic(); // Pure basic is not enough for us!
            
        return http.build();
    }
```

### Inspect AuthenticationFilter, improvise, adapt  overcome

With Spring Reactive, requests go through a chain of filters,  each filter can aprove or discard requests according to different rules. Advantage is taken to perform request authentication.
Different types of `WebFilter` are grouped by a `WebFilterChain`, in Spring Security there's `AuthenticationWebFilter` which outlines how authentication should be performed on requests matching a criteria.

`AuthenticationWebFilter` implements all the required behavior for Basic Authentication, take a look at it:


```java
public class AuthenticationWebFilter implements WebFilter {

	private final ReactiveAuthenticationManager authenticationManager;

	private ServerAuthenticationSuccessHandler authenticationSuccessHandler = new WebFilterChainServerAuthenticationSuccessHandler(); 
  // WE NEED A DIFFERENT SUCCESS HANDLER!!!!!!

	private Function<ServerWebExchange, Mono<Authentication>> authenticationConverter = new ServerHttpBasicAuthenticationConverter();

	private ServerAuthenticationFailureHandler authenticationFailureHandler = new ServerAuthenticationEntryPointFailureHandler(new HttpBasicServerAuthenticationEntryPoint());

	private ServerSecurityContextRepository securityContextRepository = NoOpServerSecurityContextRepository.getInstance();

	private ServerWebExchangeMatcher requiresAuthenticationMatcher = ServerWebExchangeMatchers.anyExchange();

....
```

The behavior that needs to be changed is what happens once an user has been authenticated using user/password credentials.
The `WebFilterChainServerAuthenticationSuccessHandler` will pass the request through the filter chain. A custom implementation is needed in this step where a Json Web Token is generated and added to the response, then the exchange will follow its way.


### Create custom SuccessHandler to make Basic Authentication return a Json Web Token

Create a custom `ServerAuthenticationSuccessHandler`, this handler is executed once the authentication with user/password has been successful,  it receives the current exchange and `Authentication` object. A JWT is generated using the `Exchange` and `Authentication` object.  In this way `BasicAuthenticationSuccessHandler` implements the desired behavior:

```java
...
 @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
    // Create and attach a JWT before passing the exchange to the filter chain
        ServerWebExchange exchange = webFilterExchange.getExchange();
        exchange.getResponse()
                .getHeaders()
                .add(HttpHeaders.AUTHORIZATION, getHttpAuthHeaderValue(authentication));
        return webFilterExchange.getChain().filter(exchange);
    }
...
```
The response from the current exchange is updated with the HTTP Authorization header with a new JWT that contains data from the `Authentication` object.


### Create a Basic Authentication filter that returns a JWT

Now create a new `AuthenticationFilter` with a custom handler:

```java
...
UserDetailsRepositoryReactiveAuthenticationManager authManager;
        AuthenticationWebFilter basicAuthenticationFilter;
        ServerAuthenticationSuccessHandler successHandler;
        
        authManager = new UserDetailsRepositoryReactiveAuthenticationManager(userDetailsRepository());
        successHandler = new  BasicAuthenticationSuccessHandler();

        basicAuthenticationFilter = new AuthenticationWebFilter(authManager);
        basicAuthenticationFilter.setAuthenticationSuccessHandler(successHandler);

...
```


### Add this filter to ServerHttpSecurity


Add this to our `ServerHttpSecurity`:

```java
...
http
                .authorizeExchange()
                    .pathMatchers("/login", "/")
                    .authenticated()
                .and()
                    .addFilterAt(basicAuthenticationFilter, SecurityWebFiltersOrder.HTTP_BASIC)
...
```

The functionality that returns a JWT when authenticating using User and Password is now implemented.


## Handle Requests with Bearer token Authorization Header

Now let's build the functionality that will take a request with the HTTP Authorization Header containing a Bearer token.
The same way the `AuthenticationWebFilter` was customized before, customize another to create a new filter.

When using JWT all information needed to authenticate and authorize a user lives within a token.
Perform the next steps:

Filter requests containing a Bearer token within its HTTP Authorization Header, verify that are well formed, confirm that it has a valid signature and then build an `Authorization` object with all information contained in the payload. If the JWT is invalid, there won't be `Authorization` resulting in an unauthorized response.

Because all information needed is contained in the JWT payload all invalid tokens will be rejected in the filtering step, but the contract defined by the `AuthenticationWebFilter` requires a non null `AuthenticationManager`. Create a dummy manager that will authenticate all exchanges. Why? Because all invalid JWT did not resulted in an authorization object and did not make it into this step.


### Generate an Authentication object using only the information contained in the token

Create a converter `ServerHttpBearerAuthenticationConverter` that takes a request `ServerWebExchange` and returns an `Authorization` object created with the information extracted from the token:

```java
...
 public Mono<Authentication> apply(ServerWebExchange serverWebExchange) {
        return Mono.justOrEmpty(serverWebExchange)
                .flatMap(AuthorizationHeaderPayload::extract)
                   .filter(matchBearerLength)
                .flatMap(isolateBearerValue)
                .flatMap(JWTUtil::check)
                .flatMap(UsernamePasswordAuthenticationBearer::create);
    }
...
```

### Create a dummy AuthenticationManager

Now implement a dummy `AuthenticationManager` called  `BearerTokenReactiveAuthenticationManager`:

```java
...
 public Mono<Authentication> authenticate(Authentication authentication) {
        return Mono.just(authentication);
    }
  
...
```

### Add the new filter to ServerHttpSecurity

Finally chain this filter in the `ServerHttpSecurity` configuration object:

```java
...
public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {

        http
                .authorizeExchange()
                    .pathMatchers("/login", "/")
                    .authenticated()
                .and()
                    .addFilterAt(basicAuthenticationFilter(), SecurityWebFiltersOrder.HTTP_BASIC)
                       .authorizeExchange()
                    .pathMatchers("/api/**")
                    .authenticated()
                .and()
                    .addFilterAt(bearerAuthenticationFilter(), SecurityWebFiltersOrder.AUTHENTICATION);

        return http.build();
    }
...
```


### Create a REST Controller and configure access rules

```java
...
 @GetMapping("/api/private")
    @PreAuthorize("hasRole('USER')")
    public Flux<FormattedMessage> privateMessage() {
        return messageService.getCustomMessage("User");
    }

...
```


### Run the Application

```shell
$ mvn spring-boot:run
```

### Test it

Login using HTTP Basic

```shell
$ curl -v  -u user:user localhost:8080/login
```

Inspect the response contents and find the authorization header. 
It should look like:

```shell
Authorization: Bearer eyJhbGciOiJIUzI1Ni.....
```

Use that in another request:

```shell
curl -v  -H "Authorization: Bearer eyJhbiJ9.eyJzdWIjTg5fQ.MXlaAaWCz0ff_o"  localhost:8080/api/admin
```

You should be able to consume the API

### That's all

Hope you enjoy it.
