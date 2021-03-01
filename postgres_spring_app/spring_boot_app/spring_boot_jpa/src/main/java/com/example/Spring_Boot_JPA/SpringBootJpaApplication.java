package com.example.Spring_Boot_JPA;

import com.example.Spring_Boot_JPA.config.AppUser;
import com.example.Spring_Boot_JPA.config.UserRole;
import com.example.Spring_Boot_JPA.mappers.impl.AppUserDtoBoMapper;
import com.example.Spring_Boot_JPA.service.PersistentDataManagerAppUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Objects;

@Configuration
@EnableAutoConfiguration
@ComponentScan
@SpringBootApplication
public class SpringBootJpaApplication implements ApplicationRunner {

	@Autowired
	private PersistentDataManagerAppUser persistentDataManagerAppUser;

	@Autowired
	private AppUserDtoBoMapper appUserDtoBoMapper;

	public static void main(String[] args) {
		SpringApplication.run(SpringBootJpaApplication.class, args);
	}

	@Bean
	public BCryptPasswordEncoder createBCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Override
	public void run(ApplicationArguments args) {
		// Creating two app users with appropriate roles.
		if(Objects.isNull(persistentDataManagerAppUser
				.getAppUserByEmailId("ankitrajput022@gmail.com")))
			persistentDataManagerAppUser.addAppUser(this
					.appUserDtoBoMapper.toBo(AppUser.builder()
					.userName("Ankit022")
					.email("ankitrajput022@gmail.com")
					.password("Rajput")
					.role(UserRole.ADMIN)
					.build()));

		if(Objects.isNull(persistentDataManagerAppUser
				.getAppUserByEmailId("ankitrajput0096@gmail.com")))
			persistentDataManagerAppUser.addAppUser(this
					.appUserDtoBoMapper.toBo(AppUser.builder()
							.userName("Ankit022")
							.email("ankitrajput0096@gmail.com")
							.password("Rajput")
							.role(UserRole.USER)
							.build()));
	}
}
