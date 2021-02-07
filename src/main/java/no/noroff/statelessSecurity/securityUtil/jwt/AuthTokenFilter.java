package no.noroff.statelessSecurity.securityUtil.jwt;

import no.noroff.statelessSecurity.securityUtil.services.UserDetailsServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/*
 This class is responsible for filtering all incoming requests to our internal token validation setup.
 It has one public facing method called doFilterInternal that Spring Security will do once per request.
 It does it once because our class extends OncePerRequestFilter.
 This filter does the following:
    - Extracts the JWT from the header
    - Extracts the username from the JWT
    - Fetches the user with that username from the database
    - Creates and Authorization object from that user, using UserServiceImpl.
    - Adds that Authorization object to Spring Security's context to be used throughout the application.
*/

@Component
public class AuthTokenFilter extends OncePerRequestFilter {
    // Dependencies
    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    /*
     Here we create a singleton constant logger
     We configure the logger to work with our AuthTokenFilter class.
    */
    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    // Overrides
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        try {
            // First we need to extract the JWT from the requests
            String jwt = parseJwt(httpServletRequest);
            /*
             If the token is present in the request header and it is valid
             according to our JwtUtil class, then we may proceed.
            */
            if(jwt != null && jwtUtil.validateJwtToken(jwt)){
                // Extract username from the JWT
                String username = jwtUtil.getUserNameFromJwtToken(jwt);
                // Use our UserDetailsService to fetch the user by their username
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                /*
                 We then use our UserDetails object and create and Authentication object out of it.
                 In this case, its a UsernamePasswordAuthenticationToken.
                */
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                /*
                 We need to tell Spring Security how this authentication object was created.
                 We did it through our http servlet.
                */
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
                // Finally, we set the security context with our new authentication object
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

        } catch (Exception e) {
            logger.error("Cannot set user authentication: " + e.getMessage());
        }

        // Here we are allowing the rest of the filter chain to continue.
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    private String parseJwt(HttpServletRequest httpServletRequest) {
        // Extract the Authorization header from the request
        String headerAuth = httpServletRequest.getHeader("Authorization");
        // Check if the Authorization header has a Bearer token
        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            /*
             If it does we return the token itself, which is the string minus "Bearer ".
             We use .substring to achieve this split
            */
            return headerAuth.substring(7);
        }
        return null;
    }
}
