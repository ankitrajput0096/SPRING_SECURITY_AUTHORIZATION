package com.example.Spring_Boot_JPA.serviceInterface;

import com.example.Spring_Boot_JPA.bo.AppUserBo;

import java.util.List;

public interface DataManagerAppUser {
    List<AppUserBo> getAppUsers();

    AppUserBo getAppUserByEmailId(final String emailId);

    AppUserBo getAppUser(final Long id);

    void addAppUser(final AppUserBo appUserBo);

    void updateAppUser(final AppUserBo appUserBo,
                       final Long id);

    void deleteAppUser(final Long id);
}
