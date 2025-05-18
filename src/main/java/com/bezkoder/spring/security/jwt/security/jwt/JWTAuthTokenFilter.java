package com.bezkoder.spring.security.jwt.security.jwt;

import com.bezkoder.spring.security.jwt.models.User;
import com.bezkoder.spring.security.jwt.security.services.UserDetailsImpl;
import com.bezkoder.spring.security.jwt.security.services.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

public class JWTAuthTokenFilter extends OncePerRequestFilter {
    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    private static final Logger logger = LoggerFactory.getLogger(JWTAuthTokenFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {

        String jwt = parseJwt(request);
        if (jwt != null) {
            try {
                if (jwtUtils.validateJwtToken(jwt)) {
                    Collection<String> claims;
                    if (!jwtUtils.isMFAToken(jwt)) {
                        claims = jwtUtils.getPermissionsFromJwtToken(jwt);
                    } else {
                        claims = List.of("ROLE_MFATOKEN");
                    }

                    UserDetails userDetails = new UserDetailsImpl(User.builder()
                        .username(jwtUtils.getUserNameFromJwtToken(jwt))
                        .id(jwtUtils.getUserIdFromJwtToken(jwt))
                        .build(), claims);

                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null,
                        userDetails.getAuthorities());
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            } catch (Exception e) {
                logger.error("Cannot set user authentication: {} {}", e.getMessage(), request);
                handleException(request, response, e);
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    private void handleException(HttpServletRequest request, HttpServletResponse response, Exception e) throws IOException {
        // Customize the error response
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        // Create a custom error response body (e.g., with error message and timestamp)
        String errorJson = String.format("{\"message\": \"%s\", \"timestamp\": \"%s\"}",
            e.getMessage(), LocalDateTime.now());
        response.getWriter().write(errorJson);
    }

    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7, headerAuth.length());
        }

        return null;
    }
}
