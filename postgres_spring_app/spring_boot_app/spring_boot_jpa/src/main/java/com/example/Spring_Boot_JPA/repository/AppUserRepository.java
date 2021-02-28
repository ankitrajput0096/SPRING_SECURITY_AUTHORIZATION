package com.example.Spring_Boot_JPA.repository;


import com.example.Spring_Boot_JPA.entity.AppUserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AppUserRepository
        extends JpaRepository<AppUserEntity,Long> {

    AppUserEntity findByEmail(final String email);
}
