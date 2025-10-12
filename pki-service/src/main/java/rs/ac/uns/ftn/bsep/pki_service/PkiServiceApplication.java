package rs.ac.uns.ftn.bsep.pki_service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class PkiServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(PkiServiceApplication.class, args);
	}

}
