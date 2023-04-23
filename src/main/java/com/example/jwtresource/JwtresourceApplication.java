package com.example.jwtresource;

import com.example.jwtresource.security.RSAKeyProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@EnableConfigurationProperties(RSAKeyProperties.class)
@SpringBootApplication
public class JwtresourceApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtresourceApplication.class, args);
    }

}
