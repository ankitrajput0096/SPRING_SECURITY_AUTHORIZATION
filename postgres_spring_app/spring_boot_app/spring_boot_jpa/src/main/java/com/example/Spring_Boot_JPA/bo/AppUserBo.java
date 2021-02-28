package com.example.Spring_Boot_JPA.bo;

import com.example.Spring_Boot_JPA.config.UserRole;
import lombok.*;

import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.validation.constraints.NotNull;

@Getter
@Setter
@ToString
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AppUserBo {

    @NotNull
    Long userid;

    @NotNull
    String username;

    @NotNull
    String email;

    @NotNull
    String password;

    @NotNull
    @Enumerated(EnumType.STRING)
    UserRole role;
}