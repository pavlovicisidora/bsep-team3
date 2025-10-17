package rs.ac.uns.ftn.bsep.pki_service.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j; // <-- DODATO
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import rs.ac.uns.ftn.bsep.pki_service.model.User;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.function.Function;

@Component
@Slf4j // <-- DODATO
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration-in-ms}")
    private long expiration;
    private SecretKey secretKey;

    @PostConstruct
    public void init() {
        byte[] keyBytes = Base64.getDecoder().decode(this.secret);
        this.secretKey = Keys.hmacShaKeyFor(keyBytes);
    }
    public String generateToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("firstName", user.getFirstName());
        claims.put("lastName", user.getLastName());
        claims.put("role", user.getRole().name());

        // KREIRANJE JEDINSTVENOG ID-ja ZA TOKEN (SESIJU)
        String jti = UUID.randomUUID().toString();

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(user.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .setId(jti) // POSTAVLJANJE JTI CLAIM-A
                .signWith(this.secretKey, SignatureAlgorithm.HS512)
                .compact();
    }


    // NOVA METODA ZA IZVLAČENJE JTI IZ TOKENA
    public String extractJti(String token) {
        return extractClaim(token, Claims::getId);
    }

    /* Izvlači email (subject) iz tokena.
            * @param token JWT token
     * @return email korisnika
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Proverava da li je token validan.
     * Token je validan ako se username u tokenu poklapa sa username-om iz UserDetails
     * I ako token nije istekao.
     * @param token JWT token
     * @param userDetails Objekat sa podacima o korisniku iz baze
     * @return true ako je validan, false inače
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        // isTokenExpired sada može da vrati true i ako je token nevalidan, što je sigurno ponašanje
        Date expirationDate = extractExpiration(token);
        if (expirationDate == null) {
            return true;
        }
        return expirationDate.before(new Date());
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Generička metoda za izvlačenje bilo kog podatka (claim) iz tokena.
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        if (claims == null) {
            return null; // Ako su claimovi null, vrati null
        }
        return claimsResolver.apply(claims);
    }

    /**
     * Glavna metoda za parsiranje tokena.
     * Koristi secret key da dekodira token i vrati sve podatke iz njega.
     * @param token JWT token
     * @return Svi podaci (claims) iz tokena
     */
    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            log.warn("JWT token has expired: {}", e.getMessage());
        } catch (SignatureException e) {
            log.warn("JWT signature validation failed: {}", e.getMessage());
        } catch (Exception e) {
            log.warn("Invalid JWT token: {}", e.getMessage());
        }
        return null; // Vrati null ako parsiranje ne uspe iz bilo kog razloga
    }

}
