package com.ahmed.AhmedSpring.config;

import com.ahmed.AhmedSpring.doa.TokenRepo;
import com.ahmed.AhmedSpring.entities.Token;
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

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

     private final JwtService js;
     private final UserDetailsService uds;
     private final TokenRepo tr;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request
            , @NonNull HttpServletResponse response
            , @NonNull FilterChain filterChain)
            throws ServletException, IOException
    {
        //first check if the token exist
        final String authHeader=request.getHeader("Authorization");
        final String jwtToken;
        final String userEmail;
        if(authHeader==null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }
        // now need to extract the token from request header
        jwtToken=authHeader.substring(7);

        // now need to extract user email to check if he in the db or not
        // i will extract email from jwtToken but i will use class i will create it called jwtService


        userEmail= js.extractEmail(jwtToken);

        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication()==null){
            UserDetails us= this.uds.loadUserByUsername(userEmail);
            boolean t=tr.findByToken(jwtToken)
                    .map(r -> !r.isExpired() && !r.isRevoked())
                    .orElse(false);
            if(js.isTokenValid(jwtToken , us) && t){
                UsernamePasswordAuthenticationToken auth=new UsernamePasswordAuthenticationToken(
                        us
                        ,null
                        ,us.getAuthorities()
                );
                auth.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(auth);
            }


        }
        filterChain.doFilter(request,response);

 }
}
