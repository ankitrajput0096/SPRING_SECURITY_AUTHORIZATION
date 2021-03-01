package com.example.Spring_Boot_JPA.config;

import com.example.Spring_Boot_JPA.bo.AppUserBo;
import com.example.Spring_Boot_JPA.service.PersistentDataManagerAppUser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class SecurityUserDetailsService implements UserDetailsService {

    @Autowired
    private PersistentDataManagerAppUser persistentDataManagerAppUser;

    @Override
    public UserDetails loadUserByUsername(String email)
            throws UsernameNotFoundException {
        log.debug("Authenticating user with email={}",
                email.replaceFirst("@.*", "@***"));

        // Retrieving user details from DB.
        AppUserBo appUserBo = this.persistentDataManagerAppUser
                .getAppUserByEmailId(email);
        // This can also be an ApI call to other micro-service to
        // fetch user details.

        return new User(appUserBo.getUsername(), appUserBo.getPassword(),
                AuthorityUtils.createAuthorityList(appUserBo.getRole().toString()));
    }

}
