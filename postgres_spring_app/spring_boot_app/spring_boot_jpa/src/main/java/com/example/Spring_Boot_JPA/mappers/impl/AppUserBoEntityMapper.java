package com.example.Spring_Boot_JPA.mappers.impl;

import com.example.Spring_Boot_JPA.bo.AppUserBo;
import com.example.Spring_Boot_JPA.entity.AppUserEntity;
import com.example.Spring_Boot_JPA.mappers.BoEntityMapperIface;
import org.springframework.stereotype.Component;

import java.util.Objects;

@Component
public class AppUserBoEntityMapper
        implements BoEntityMapperIface<AppUserBo, AppUserEntity> {

    @Override
    public AppUserBo toBo(AppUserEntity appUserEntity) {
        if(Objects.isNull(appUserEntity))
            return null;
        return AppUserBo.builder()
                .userid(appUserEntity.getUserid())
                .email(appUserEntity.getEmail())
                .password(appUserEntity.getPassword())
                .role(appUserEntity.getRole())
                .username(appUserEntity.getUserName())
                .build();
    }

    @Override
    public AppUserEntity toEntity(AppUserBo appUserBo) {
        if(Objects.isNull(appUserBo))
            return null;
        return AppUserEntity.builder()
                .email(appUserBo.getEmail())
                .password(appUserBo.getPassword())
                .role(appUserBo.getRole())
                .userName(appUserBo.getUsername())
                .build();
    }
}
