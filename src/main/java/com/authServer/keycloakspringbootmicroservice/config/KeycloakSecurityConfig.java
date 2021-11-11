package com.authServer.keycloakspringbootmicroservice.config;

import com.authServer.keycloakspringbootmicroservice.Filters.UrlFilter;

import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.keycloak.OAuth2Constants;
import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(jsr250Enabled = true)
public class KeycloakSecurityConfig extends KeycloakWebSecurityConfigurerAdapter {

    @Autowired
    private UrlFilter urlFilter;

    @Value("${keycloak.auth-server-url}")
    String serverUrl;
    @Value("${keycloak.realm}")
    String realm;
    @Value("${keycloak.resource}")
    String clientId;
    @Value("${keycloak.credentials.secret}")
    String clientSecret;
    String userName = "demo-realm-admin";
    String password = "password";

    /*
     * @Override protected void configure(HttpSecurity httpSecurity) throws
     * Exception { super.configure(httpSecurity);
     * httpSecurity.authorizeRequests().antMatchers("/Test/anonymous").permitAll().
     * antMatchers("/Test/user")
     * .hasAnyRole("user").antMatchers("/Test/admin").hasAnyRole("admin").
     * antMatchers("/Test/all-user") .hasAnyRole("user",
     * "admin").anyRequest().permitAll(); httpSecurity.csrf().disable(); }
     */
    /************************************************************************************************************/

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/**").permitAll().anyRequest().fullyAuthenticated().and().formLogin()
                .usernameParameter("username").passwordParameter("password").permitAll();
        http.addFilterBefore(urlFilter, UsernamePasswordAuthenticationFilter.class);

        http.csrf().disable();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    /************************************************************************************************************/

    @Bean
    @Override
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        KeycloakAuthenticationProvider keycloakAuthenticationProvider = keycloakAuthenticationProvider();
        keycloakAuthenticationProvider.setGrantedAuthoritiesMapper(new SimpleAuthorityMapper());
        auth.authenticationProvider(keycloakAuthenticationProvider);
        auth.inMemoryAuthentication().withUser(userName).password(password).roles("demo-realm-admin");
    }

    @Bean
    public KeycloakConfigResolver keycloakConfigResolver() {
        return new KeycloakSpringBootConfigResolver();
    }

    @Bean
    public Keycloak getKeycloakInstance() {
        return KeycloakBuilder.builder().serverUrl(serverUrl).realm(realm).grantType(OAuth2Constants.PASSWORD)
                .username(userName).password(password).clientId(clientId).clientSecret(clientSecret)
                .resteasyClient(new ResteasyClientBuilder().connectionPoolSize(10).build()).build();
    }

    @Bean
    public WebClient.Builder getBuilder() {
        return WebClient.builder();
    }

}
