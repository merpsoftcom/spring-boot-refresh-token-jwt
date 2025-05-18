package com.bezkoder.spring.security.jwt.security.jwt;

import com.bezkoder.spring.security.jwt.exception.StandardException;
import com.bezkoder.spring.security.jwt.models.Permission;
import com.bezkoder.spring.security.jwt.models.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Date;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);
    public static final String PERMISSIONS = "permissions";
    public static final String IS_MFA_TOKEN = "isMFAToken";
    public static final String ID = "id";

    @Value("${bezkoder.app.jwtSecret}")
    private String jwtSecret;

    @Value("${bezkoder.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    @Value("${bezkoder.app.jwtMFAExpirationMs}")
    private int jwtMFAExpirationMs;

    public String generateJwtToken(User user) {
        return Jwts.builder()
            .setSubject(user.getUsername())
            .setIssuedAt(new Date())
            .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
            .signWith(SignatureAlgorithm.HS512, jwtSecret)
            .claim(PERMISSIONS, user.getRole().getPermissions().stream().map(Permission::toString).toList())
            .claim(ID, user.getId())
            .compact();
    }

    public String generateMFAToken(User user) {
        return Jwts.builder()
            .setSubject(user.getUsername())
            .setIssuedAt(new Date())
            .signWith(SignatureAlgorithm.HS512, jwtSecret)
            .setExpiration(new Date((new Date()).getTime() + jwtMFAExpirationMs ))
            .claim(IS_MFA_TOKEN, "true")
            .claim(ID, user.getId())
            .compact();
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser()
            .setSigningKey(jwtSecret)
            .parseClaimsJws(token)
            .getBody()
            .getSubject();
    }

    public Long getUserIdFromJwtToken(String token) {
        return Long.parseLong(Jwts.parser()
            .setSigningKey(jwtSecret)
            .parseClaimsJws(token)
            .getBody()
            .get(ID).toString());
    }

    public Collection<String> getPermissionsFromJwtToken(String token) {
        return Jwts.parser()
            .setSigningKey(jwtSecret)
            .parseClaimsJws(token)
            .getBody()
            .get(PERMISSIONS, Collection.class);
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(authToken);
            return true;
        } catch (Exception e) {
            throw new StandardException(HttpStatus.UNAUTHORIZED, e.getMessage());
        }
    }

    public boolean isMFAToken(String jwt) {
        return Boolean.parseBoolean(
            Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(jwt)
                .getBody()
                .get(IS_MFA_TOKEN, String.class));
    }
}
