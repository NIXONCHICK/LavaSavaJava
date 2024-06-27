package org.api.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.api.entities.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

  private final String SECRET_KEY = "FC5B65A220DE93520EAB687DB08804D4CC40FCB680A0063E5C5F69A1430097A7";

  public String extractEmail(String token) {
    return extractClaim(token, Claims::getSubject);
  }
  
  public Long extractId(String token) {
    return extractClaim(token, claims -> claims.get("id", Long.class));
  }

  public String extractTokenFromCookies(HttpServletRequest request) {
    Cookie[] cookies = request.getCookies();
    if (cookies != null) {
      Cookie tokenCookie = Arrays.stream(cookies)
          .filter(cookie -> "token".equals(cookie.getName()))
          .findFirst()
          .orElse(null);

      if (tokenCookie != null) {
        return tokenCookie.getValue();
      }
    }
    
    return null;
  }

  public boolean isValid(String token, UserDetails user) {
    String email = extractEmail(token);
    
    return email.equals(user.getUsername()) && !isTokenExpired(token);
  }

  private boolean isTokenExpired(String token) {
    return extractExpiration(token).before(new Date());
  }

  private Date extractExpiration(String token) {
    return extractClaim(token, Claims::getExpiration);
  }

  public  <T> T extractClaim(String token, Function<Claims, T> resolver) {
    Claims claims = extractAllClaims(token);
    return resolver.apply(claims);
  }

  private Claims extractAllClaims(String token) {
    return Jwts.parser()
        .verifyWith(getSigningKey())
        .build()
        .parseSignedClaims(token)
        .getPayload();
  }

  public String generateToken(User user) {
    Map<String, Long> claims = Map.of("id", user.getId());
    
    return Jwts.builder()
        .claims(claims)
        .subject(user.getEmail())
        .issuedAt(new Date(System.currentTimeMillis()))
        .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24))
        .signWith(getSigningKey())
        .compact();
  }

  private SecretKey getSigningKey() {
    byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
    return Keys.hmacShaKeyFor(keyBytes);
  }
}
