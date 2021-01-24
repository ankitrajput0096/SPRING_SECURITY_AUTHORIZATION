package com.security.service;

import com.security.CurrentUser;
import com.security.Role;
import com.security.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;


@Service
public class CurrentUserDetailsService implements UserDetailsService {

    private static final Logger LOGGER = LoggerFactory.getLogger(CurrentUserDetailsService.class);

    @Override
    public UserDetails loadUserByUsername(String email)
            throws UsernameNotFoundException {
        LOGGER.debug("Authenticating user with email={}", email.replaceFirst("@.*", "@***"));
        User user = new User();
        user.setUsername("Ankit");
        user.setUserid(1l);
        user.setEmail("ankitrajput022@gmail.com");
        user.setRole(Role.ADMIN);
        user.setPassword(new BCryptPasswordEncoder().encode("rajput"));

        // api call with base 64 encoded client_id and client_secret

        return new CurrentUser(user);
    }

}
