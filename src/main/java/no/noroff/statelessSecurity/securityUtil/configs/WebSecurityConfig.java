package no.noroff.statelessSecurity.securityUtil.configs;

import no.noroff.statelessSecurity.securityUtil.jwt.AuthEntryPointJwt;
import no.noroff.statelessSecurity.securityUtil.jwt.AuthTokenFilter;
import no.noroff.statelessSecurity.securityUtil.services.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/*
 This is the configuration in charge for all our security.
 We use all our other services and configuration classes here.
*/

@EnableWebSecurity
@EnableGlobalMethodSecurity(
        jsr250Enabled = true,
        prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    /*
     We need a way to tie into the existing authentication scheme. This is done by using our
     UserDetailsServiceImpl which implements UserDetailsService. The configure method for building
     authentication requires we supply a UserDetailsService object, we do so through polymorphism and dependency injection.
    */
    @Autowired
    UserDetailsServiceImpl userDetailsService;

    /*
        Because we are changing to JWTs and stateless authentication,
        we need to provide and entry point. This entry point is used when we configure http security.
     */
    @Autowired
    private AuthEntryPointJwt authEntryPointJwt;

    /*
     Here we tell Spring Security how to handle our users, through the UserDetailsServiceImpl
     we have created. It also needs a password encoding method otherwise it simply will encode passwords
     as plain text.
    */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    // The chosen password encoder is Bcrypt
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // Configuring http using the builder pattern
        http
                // Enable CORS and disable CSRF
                .cors().and().csrf().disable()
                // Set unauthorized requests exception handler
                .exceptionHandling().authenticationEntryPoint(authEntryPointJwt).and()
                // Set session management to stateless
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                // Set permissions on endpoints
                .authorizeRequests()
                // Our public endpoints
                .antMatchers("/api/auth/**").permitAll()
                // Our protected endpoints
                .antMatchers("/api/test/**").permitAll()
                .anyRequest().authenticated();

        // Add JWT token filter
        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    /*
     By default the AuthenticationManager is not publicly exposed, we override this method to expose it.
     This exposed manager is used in the AuthController to create and check users
    */
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
