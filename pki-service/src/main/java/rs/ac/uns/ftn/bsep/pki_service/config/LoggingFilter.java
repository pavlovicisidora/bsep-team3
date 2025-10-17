package rs.ac.uns.ftn.bsep.pki_service.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class LoggingFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            // 1. Izvlacenje IP adrese
            String ipAddress = request.getHeader("X-Forwarded-For");
            if (ipAddress == null || ipAddress.isEmpty()) {
                ipAddress = request.getRemoteAddr();
            }
            MDC.put("clientIp", ipAddress);

            // 2. Izvlacenje Korisnickog imena (email-a)
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = "ANONYMOUS";
            if (authentication != null && authentication.isAuthenticated() && !authentication.getPrincipal().equals("anonymousUser")) {
                // Pretpostavljam da ti je email korisnicko ime
                username = authentication.getName();
            }
            MDC.put("user", username);

            // Nastavi sa izvrsavanjem zahteva
            filterChain.doFilter(request, response);

        } finally {
            // OBAVEZNO: Ocisti MDC nakon zahteva jer se threadovi recikliraju
            MDC.clear();
        }
    }
}