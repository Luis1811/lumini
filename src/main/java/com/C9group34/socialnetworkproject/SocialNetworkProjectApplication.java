package com.C9group34.socialnetworkproject;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

@SpringBootApplication(exclude = SecurityAutoConfiguration.class)
public class SocialNetworkProjectApplication {

	public static void main(String[] args) {
		SpringApplication.run(SocialNetworkProjectApplication.class, args);
	}

}
