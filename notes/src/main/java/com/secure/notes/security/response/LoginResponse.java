package com.secure.notes.security.response;

import lombok.*;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class LoginResponse {
    private String jwtToken;

    private String username;
    private List<String> roles;

    // getters ans setters
    public LoginResponse(String username, List<String> roles, String jwtToken) {
        this.username = username;
        this.roles = roles;
        this.jwtToken = jwtToken;
    }


}