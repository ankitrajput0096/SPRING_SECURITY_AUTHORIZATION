package com.example.Spring_Boot_JPA.mappers.impl;

import com.example.Spring_Boot_JPA.bo.AppUserBo;
import com.example.Spring_Boot_JPA.config.AppUser;
import com.example.Spring_Boot_JPA.mappers.DtoBoMapperIface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class AppUserDtoBoMapper
        implements DtoBoMapperIface<AppUserBo, AppUser> {

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public AppUserBo toBo(AppUser appUser) {
        return AppUserBo.builder()
                .username(appUser.getUserName())
                .role(appUser.getRole())
                .password(this.bCryptPasswordEncoder
                        .encode(appUser.getPassword()))
                .email(appUser.getEmail())
                .build();
    }

    @Override
    public AppUser toDto(AppUserBo appUserBo) {
        return AppUser.builder()
                .userId(appUserBo.getUserid())
                .userName(appUserBo.getUsername())
                .role(appUserBo.getRole())
                .password(appUserBo.getPassword())
                .email(appUserBo.getEmail())
                .build();
    }
}
