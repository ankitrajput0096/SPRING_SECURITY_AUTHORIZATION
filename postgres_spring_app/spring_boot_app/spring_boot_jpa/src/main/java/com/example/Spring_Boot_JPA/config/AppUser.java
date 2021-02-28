package com.example.Spring_Boot_JPA.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

import javax.validation.constraints.NotNull;

@Getter
@Setter
@ToString
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AppUser {

    @JsonProperty("user_id")
    private Long userId;

    @JsonProperty("user_name")
    @NotNull
    private String userName;

    @JsonProperty("email")
    @NotNull
    private String email;

    @JsonProperty("password")
    @NotNull
    private String password;

    @JsonProperty("role")
    @NotNull
    private UserRole role;
}

