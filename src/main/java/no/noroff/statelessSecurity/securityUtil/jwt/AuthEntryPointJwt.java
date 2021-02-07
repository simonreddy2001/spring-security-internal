package no.noroff.statelessSecurity.securityUtil.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/*
    This class is responsible for handling authentication errors.
    When something goes wrong with the Jwts that come in, this class decides what to do.
    For example, if there is no Jwt present, it returns that the client is unauthorized.
    They will then need to go and get a valid token by logging in.
 */

@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

    private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);

    @Override
    public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
        // We log what was wrong with the authorization
        logger.error("Unauthorized error: {}", e.getMessage());
        // Send a response to the client to let them know they are unauthorized, this is the 401 we see.
        httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Error: Unauthorized");
    }
}
