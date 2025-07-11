package org.etjen.eAPITemplate;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
@ConfigurationPropertiesScan("org.etjen.eAPITemplate.config.properties")
public class EApiTemplateApplication {

	public static void main(String[] args) {
		SpringApplication.run(EApiTemplateApplication.class, args);
	}

}
