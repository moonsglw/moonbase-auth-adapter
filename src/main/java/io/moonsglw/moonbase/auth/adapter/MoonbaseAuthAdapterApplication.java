package io.moonsglw.moonbase.auth.adapter;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;

@SpringBootApplication
@EnableAutoConfiguration(exclude={UserDetailsServiceAutoConfiguration.class, SecurityAutoConfiguration.class})
public class MoonbaseAuthAdapterApplication {

	public static void main(String[] args) {
		SpringApplication.run(MoonbaseAuthAdapterApplication.class, args);
	}

}
