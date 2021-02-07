package no.noroff.statelessSecurity.securityUtil.jwt;

import io.jsonwebtoken.*;
import no.noroff.statelessSecurity.securityUtil.services.UserDetailsImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.util.Date;

/*
 This class serves as a utility for manipulating JWTs.
 We use a standard logger to log everything that goes wrong.
 This class can generate a token based on secrets we provide in application.properties,
 validate an existing token with our secret, and extract a username from a jwt.

 NOTE: If you decide to include roles here, you can extract them out in the same way as username is.
 This is true for any extra information. This can be done to save a trip to the database.
*/

@Component
public class JwtUtil {
    // Fields
    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    /*
     We store these values in our application.properties files.
     These would ideally be environment variables on a server, which is why we access them this way.
    */
    @Value("${noroff.app.jwtSecret}")
    private String jwtSecret;
    @Value("${noroff.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    // Here we make use of the standard JWT library for java called io.jsonwebtoken.
    public String generateJwtToken(Authentication authentication) {
        // Here we access the current user through Spring Security.
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();
        // We use the builder pattern to create a JWT
        return Jwts.builder()
                // We set our subject as our user's username - this who the token is for
                .setSubject((userPrincipal.getUsername()))
                // We set the issued at date to now
                .setIssuedAt(new Date())
                // Expiration date is determined by our jwtExpirationMs value
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                // And we finally sign the token with our secret, this secret is important for validation.
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public String getUserNameFromJwtToken(String jwt) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(jwt).getBody().getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }
}
