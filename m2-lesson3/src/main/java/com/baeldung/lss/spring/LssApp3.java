package com.baeldung.lss.spring;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import com.baeldung.lss.persistence.UserRepository;
import com.baeldung.lss.web.model.User;

@SpringBootApplication
@ComponentScan("com.baeldung.lss")
@EnableJpaRepositories("com.baeldung.lss")
@EntityScan("com.baeldung.lss.web.model")
public class LssApp3 {

    @Autowired
    private UserRepository userRepository;

    @Bean
    public Converter<String, User> messageConverter() {
        return new Converter<String, User>() {
            @Override
            public User convert(String id) {
                return userRepository.findOne(Long.valueOf(id));
            }
        };
    }

    public static void main(String[] args) throws Exception {
        SpringApplication.run(new Class[] { LssApp3.class, LssSecurityConfig.class, LssWebMvcConfiguration.class }, args);
    }

}