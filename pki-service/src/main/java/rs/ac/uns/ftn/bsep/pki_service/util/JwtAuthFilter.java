package rs.ac.uns.ftn.bsep.pki_service.util;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import rs.ac.uns.ftn.bsep.pki_service.util.JwtUtil; // Proverite import
import rs.ac.uns.ftn.bsep.pki_service.service.SessionService;
import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil; // Vidite? Majstor KORISTI alat.
    private final UserDetailsService userDetailsService;
    private final SessionService sessionService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        if (request.getServletPath().contains("/api/auth")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String authHeader = request.getHeader("Authorization");

        // Ako nema tokena, samo prosledi zahtev dalje.
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String jwt = authHeader.substring(7);

        // Sada je parsiranje bezbedno. Ako ne uspe, username će biti null.
        final String username = jwtUtil.extractUsername(jwt);
        final String jti = jwtUtil.extractJti(jwt);

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            // Proveravamo validnost tokena samo ako je username uspešno izvučen
            if (jwtUtil.isTokenValid(jwt, userDetails)) {
                // Proveravamo i validnost tokena i postojanje sesije u bazi
                boolean isSessionActive = sessionService.findById(jti).isPresent();

                if (jwtUtil.isTokenValid(jwt, userDetails) && isSessionActive) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);

                    sessionService.updateLastActivity(jti);
                }
            }
            // Ova linija se sada UVEK izvršava, čak i ako je token nevalidan.
            filterChain.doFilter(request, response);
        }
    }
}