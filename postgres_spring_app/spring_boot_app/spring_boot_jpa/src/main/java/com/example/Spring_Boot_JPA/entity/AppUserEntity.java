package com.example.Spring_Boot_JPA.entity;

import com.example.Spring_Boot_JPA.config.UserRole;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.util.Date;

@Entity
@Table(name="app_user")
@Setter
@Getter
@ToString
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AppUserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    @Column(name = "user_id")
    private Long userid;

    @NotNull
    @Column(name = "user_name", nullable = false)
    private String userName;

    @Column(name = "email", unique = true)
    private String email;

    @Column(name = "password")
    private String password;

    @Column(name = "role")
    private UserRole role;

    @Column(name = "created_at", nullable = false)
    @CreationTimestamp
    @CreatedDate
    private Date createdAt;

    @Column(name = "updated_at", nullable = false)
    @UpdateTimestamp
    @LastModifiedDate
    private Date updatedAt;
}