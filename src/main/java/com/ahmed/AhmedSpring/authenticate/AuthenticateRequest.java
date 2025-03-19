package com.ahmed.AhmedSpring.authenticate;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AuthenticateRequest {
    private String email;
    private String password;
}
