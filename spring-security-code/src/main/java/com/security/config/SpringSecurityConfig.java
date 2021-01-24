package com.security.config;

import org.springframework.beans.factory.annotation.Autowired;
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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    // Create 2 users for demo
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

//        auth.inMemoryAuthentication()
//                .withUser("Ankit").password("{noop}rajput").roles("USER")
//                .and()
//                .withUser("Ankit").password("{noop}rajput").roles("USER", "ADMIN");

        auth
                .userDetailsService(userDetailsService)
                .passwordEncoder(new BCryptPasswordEncoder());
    }

    // Secure the endpoins with HTTP Basic authentication
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                //HTTP Basic authentication
                .httpBasic()
                .and()
                .authorizeRequests()

                .antMatchers(HttpMethod.GET, "/books/**").hasAnyAuthority("ADMIN", "USER")
                .antMatchers(HttpMethod.POST, "/books").hasAuthority("USER")
                .antMatchers(HttpMethod.PUT, "/books/**").hasAnyRole("ADMIN", "USER")
                .antMatchers(HttpMethod.PATCH, "/books/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.DELETE, "/books/**").hasAuthority("ADMIN")
                .antMatchers("/", "/home", "/public/**","/login").permitAll()
               // .anyRequest().fullyAuthenticated()   //Returns true if the user is not an anonymous or a remember-me user
                .and()
//                .anonymous().disable()
                .csrf().disable()
                .formLogin().disable()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(new AuthenticationEntryPoint() {
                    @Override
                    public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                        // 401
                        httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication Failed, Yaar Ankit");
                    }
                })
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException e) throws IOException, ServletException {
                        // 403
                        httpServletResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "Authorization Failed, Yaar Ankit : " + e.getMessage());
                    }
                });
    }

    /*


ankit@ankit-Inspiron-3542:~$ curl localhost:8080/books/2
{"timestamp":"2021-01-24T09:35:05.517+0000","status":401,"error":"Unauthorized","message":"Authentication Failed, Yaar Ankit","path":"/books/2"}

ankit@ankit-Inspiron-3542:~$ curl --request POST localhost:8080/books -u Ankit:rajput
{"timestamp":"2021-01-24T09:35:26.074+0000","status":403,"error":"Forbidden","message":"Authorization Failed, Yaar Ankit : Access is denied","path":"/books"}ankit@ankit-Inspiron-3542:~$

ankit@ankit-Inspiron-3542:~$ curl --request GET localhost:8080/books -u Ankit:rajput
[{"id":1,"name":"A Guide to the Bodhisattva Way of Life","author":"Santideva","price":15.41},{"id":2,"name":"The Life-Changing Magic of Tidying Up","author":"Marie Kondo","price":9.69},{"id":3,"name":"Refactoring: Improving the Design of Existing Code","author":"Martin Fowler","price":47.99}]ankit@ankit-Inspiron-3542:~$

     */


    /*@Bean
    public UserDetailsService userDetailsService() {
        //ok for demo
        User.UserBuilder users = User.withDefaultPasswordEncoder();

        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(users.username("user").password("password").roles("USER").build());
        manager.createUser(users.username("admin").password("password").roles("USER", "ADMIN").build());
        return manager;
    }*/

}
