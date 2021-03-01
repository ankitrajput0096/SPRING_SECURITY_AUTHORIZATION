package com.example.Spring_Boot_JPA.service;

import com.example.Spring_Boot_JPA.bo.AppUserBo;
import com.example.Spring_Boot_JPA.entity.AppUserEntity;
import com.example.Spring_Boot_JPA.mappers.impl.AppUserBoEntityMapper;
import com.example.Spring_Boot_JPA.repository.AppUserRepository;
import com.example.Spring_Boot_JPA.serviceInterface.DataManagerAppUser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Slf4j
@Service
public class PersistentDataManagerAppUser implements DataManagerAppUser {


    @Autowired
    private AppUserRepository appUserRepository;

    @Autowired
    private AppUserBoEntityMapper appUserBoEntityMapper;

    @Override
    @Transactional
    public List<AppUserBo> getAppUsers() {
        return this.appUserRepository.findAll().stream()
                .map(e -> this.appUserBoEntityMapper.toBo(e))
                .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public AppUserBo getAppUser(final Long id) {
        return this.appUserBoEntityMapper.toBo(
                this.appUserRepository.findById(id).orElse(null));
    }

    @Override
    @Transactional
    public AppUserBo getAppUserByEmailId(final String emailId) {
        return this.appUserBoEntityMapper.toBo(
                this.appUserRepository.findByEmail(emailId));
    }

    @Override
    @Transactional
    public void addAppUser(final AppUserBo appUserBo) {
        if(Objects.isNull(this.appUserRepository.findByEmail(appUserBo.getEmail())))
            this.appUserRepository.save(this.appUserBoEntityMapper.toEntity(appUserBo));
        else
            log.error("App User with duplicate email id");
    }

    @Override
    @Transactional
    public void updateAppUser(final AppUserBo appUserBo, final Long id) {
        AppUserEntity entity = this.appUserRepository.findById(id).orElse(null);
        if(Objects.isNull(entity)) {
            log.info("The app users with id : {} is not present in DB.", id);
            return;
        }
        entity.setUserName(appUserBo.getUsername());
        entity.setRole(appUserBo.getRole());
        entity.setPassword(appUserBo.getPassword());
        this.appUserRepository.save(entity);
    }

    @Override
    @Transactional
    public void deleteAppUser(final Long id) {
        this.appUserRepository.deleteById(id);
    }
}
