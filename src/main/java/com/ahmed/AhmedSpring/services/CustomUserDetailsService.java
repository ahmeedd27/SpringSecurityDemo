package com.ahmed.AhmedSpring.services;

import com.ahmed.AhmedSpring.doa.UserRepo;
import com.ahmed.AhmedSpring.entities.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepo us;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
         User u= us.findByEmail(username).orElseThrow(() -> new RuntimeException("Not Found"));
         return u;
    }//


}
