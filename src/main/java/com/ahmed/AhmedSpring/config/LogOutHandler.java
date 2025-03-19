package com.ahmed.AhmedSpring.config;

import com.ahmed.AhmedSpring.doa.TokenRepo;
import com.ahmed.AhmedSpring.entities.Token;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LogOutHandler  implements LogoutHandler {
    private final TokenRepo tr;
    @Override
    public void logout(
            HttpServletRequest request
            , HttpServletResponse response
            , Authentication authentication) {
        final String authHeader=request.getHeader("Authorization");
        final String jwtToken;

        if(authHeader==null || !authHeader.startsWith("Bearer ")){
           return;
        }
         jwtToken=authHeader.substring(7);
        Token t=tr.findByToken(jwtToken).orElseThrow();
        if(t!=null){
            t.setRevoked(true);
            t.setExpired(true);
            tr.save(t);
        }
    }
}
