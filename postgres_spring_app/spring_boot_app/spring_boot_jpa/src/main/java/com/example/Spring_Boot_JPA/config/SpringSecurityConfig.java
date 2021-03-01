package com.example.Spring_Boot_JPA.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        //-> For in memory authentication.
//        auth.inMemoryAuthentication()
//                .withUser("Ankit")
//                .password("{noop}rajput").roles("USER")
//                .and()
//                .withUser("Ankit")
//                .password("{noop}rajput").roles("USER", "ADMIN");

        auth.userDetailsService(userDetailsService)
                .passwordEncoder(bCryptPasswordEncoder);
    }

    // Secure the endpoints with HTTP Basic authentication
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                //HTTP Basic authentication
                .httpBasic()
                .and()
                .authorizeRequests()
                .antMatchers(HttpMethod.GET, "/springBootJpa/books/**", "/springBootJpa/books")
                .hasAnyAuthority("ADMIN", "USER")
                .antMatchers(HttpMethod.POST, "/springBootJpa/books/**").hasAuthority("USER")
                .antMatchers(HttpMethod.PUT, "/springBootJpa/books/**")
                .hasAnyAuthority("ADMIN", "USER")
                .antMatchers(HttpMethod.DELETE, "/springBootJpa/books/**").hasAuthority("ADMIN")
                .antMatchers(HttpMethod.GET , "/springBootJpa/AppUsers/**", "/springBootJpa/AppUsers")
                .hasAuthority( "USER")
                .antMatchers(HttpMethod.POST , "/springBootJpa/AppUsers")
                .hasAuthority( "ADMIN")
                .antMatchers(HttpMethod.PUT , "/springBootJpa/AppUsers/**")
                .hasAuthority( "ADMIN")
                .antMatchers(HttpMethod.DELETE , "/springBootJpa/AppUsers/**")
                .hasAuthority( "ADMIN")
                .antMatchers("/springBootJpa/topics", "/springBootJpa/topics/**",
                        "/springBootJpa/", "/springBootJpa/transaction/**").permitAll()
                .and()
                .csrf().disable()
                .formLogin().disable()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(new AuthenticationEntryPoint() {
                    @Override
                    public void commence(HttpServletRequest httpServletRequest,
                                         HttpServletResponse httpServletResponse,
                                         AuthenticationException e) throws IOException {
                        // 401
                        httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                                "Authentication Failed, Yaar Ankit");
                    }
                })
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest httpServletRequest,
                                       HttpServletResponse httpServletResponse,
                                       AccessDeniedException e) throws IOException {
                        // 403
                        httpServletResponse.sendError(HttpServletResponse.SC_FORBIDDEN,
                                "Authorization Failed, Yaar Ankit : " + e.getMessage());
                    }
                });
    }
}
