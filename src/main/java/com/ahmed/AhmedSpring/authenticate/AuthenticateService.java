package com.ahmed.AhmedSpring.authenticate;

import com.ahmed.AhmedSpring.config.JwtService;
import com.ahmed.AhmedSpring.doa.TokenRepo;
import com.ahmed.AhmedSpring.doa.UserRepo;
import com.ahmed.AhmedSpring.entities.Role;
import com.ahmed.AhmedSpring.entities.Token;
import com.ahmed.AhmedSpring.entities.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthenticateService {
    private final UserRepo ur;
    private final JwtService js;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authMan;
    private final TokenRepo tr;

    public AuthenticationResponse register(RegisterRequest rr) {
        User user=User
                .builder()
                .name(rr.getName())
                .email(rr.getEmail())
                .password(passwordEncoder.encode(rr.getPassword()))
                .role(Role.USER)
                .build();
        ur.save(user);
        String jwtToken=js.generateToken(user);
      saveUserToken(user , jwtToken);
       return  AuthenticationResponse
                .builder()
                .token(jwtToken)
                .build();

     }

    private void saveUserToken(User user, String jwtToken) {
        Token t=Token
                .builder()
                .u(user)
                .token(jwtToken)
                .revoked(false)
                .expired(false)
                .build();
        tr.save(t);

    }

    public AuthenticationResponse authenticate(AuthenticateRequest rr) {
        authMan.authenticate(
                new UsernamePasswordAuthenticationToken(
                        rr.getEmail(),
                        rr.getPassword()
                )
        );
        // so if the user pass from authman and the email and password are correct we will do the following
        User u=ur.findByEmail(rr.getEmail()).orElseThrow(() -> new UsernameNotFoundException("NotFound"));
        String jwtToken=js.generateToken(u);
        revokeAllUserTokens(u);
        saveUserToken(u,jwtToken);
        return  AuthenticationResponse
                .builder()
                .token(jwtToken)
                .build();
    }

    public void revokeAllUserTokens(User user){
        List<Token> validUserToken=tr.findAllValidTokenByUserId(user.getId());
        validUserToken.forEach( s -> {
            s.setRevoked(true);
            s.setExpired(true);
        });
        tr.saveAll(validUserToken);
    }

}
