package com.example.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "energy.jwt")
public class TokenProperties {

    private String tokenSecret;
    private Long tokenValidity;
    private String tokenRsa;

}