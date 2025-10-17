package rs.ac.uns.ftn.bsep.pki_service;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

@SpringBootApplication
@EnableAsync
@EnableScheduling
public class PkiServiceApplication {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static void main(String[] args) {

		SpringApplication.run(PkiServiceApplication.class, args);
	}

}
