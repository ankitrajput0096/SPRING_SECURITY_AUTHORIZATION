package com.security;

import org.springframework.security.core.authority.AuthorityUtils;


/**
 * @author Dinesh.Rajput
 *
 */
public class CurrentUser extends org.springframework.security.core.userdetails.User {

    /**
     *
     */
    private static final long serialVersionUID = 1L;

    private User user;

    public CurrentUser(User user) {
        super(user.getEmail(), user.getPassword(), AuthorityUtils.createAuthorityList(user.getRole().toString()));
        this.user = user;
    }

    public User getUser() {
        return user;
    }

    public Long getId() {
        return user.getUserid();
    }

    public Role getRole() {
        return user.getRole();
    }

    @Override
    public String toString() {
        return "CurrentUser{" +
                "user=" + user +
                "} " + super.toString();
    }
}

