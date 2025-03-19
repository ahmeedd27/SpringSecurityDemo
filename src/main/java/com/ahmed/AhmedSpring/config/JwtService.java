package com.ahmed.AhmedSpring.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.*;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY="B3MxR7Qp2xLmW8fzP1lVYKPd4wZgJcRMB0A2s7NyU3I=";


    public String extractEmail(String jwtToken) {
        return extractClaim(jwtToken, Claims::getSubject);
     }

     public <T> T extractClaim(String token , Function<Claims , T> claimsResolver) {
        final Claims claims=extractAllClaimsInTheToken(token);
        return claimsResolver.apply(claims); //function take parameter of type claims and return ant type(generic)
     }

     private Claims extractAllClaimsInTheToken(String jwtToken){
        return   Jwts
                .parserBuilder()
                .setSigningKey(getSignIngKey())
                .build()
                .parseClaimsJws(jwtToken)
                .getBody();
     }

     public String generateToken(UserDetails us){
        return generateToken(new HashMap<>() , us);
     }

     public String generateToken(
             Map<String , Object> extraClaims ,
             UserDetails us
       ){
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(us.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*60))
                .signWith(getSignIngKey() , SignatureAlgorithm.HS256)
                .compact();

     }


     public boolean isTokenValid(String token , UserDetails us){
        final String username=extractEmail(token);
        return (username.equals(us.getUsername())) && !isTokenExpired(token);
     }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token , Claims::getExpiration);
    }

    private Key getSignIngKey() {
        byte[] keyBytes= Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }


}
