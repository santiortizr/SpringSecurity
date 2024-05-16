package com.example.Security.service;

import com.example.Security.dto.AuthReq;
import com.example.Security.dto.AuthenticationResp;
import com.example.Security.dto.RegisterReq;
import com.example.Security.entities.Role;
import com.example.Security.entities.User;
import com.example.Security.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.parameters.P;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResp register(RegisterReq req){
        User user = this.mapToUser(req);
        userRepository.save(user);
        String jwtToken = jwtService.generateToken(user);
        return mapToAuthenticationResponse(jwtToken);
    }

    public AuthenticationResp authenticate(AuthReq req){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        req.getEmail(),
                        req.getPassword()
                )
        );
        User user = userRepository.findByEmail(req.getEmail())
                .orElseThrow();
        String jwtToken = jwtService.generateToken(user);
        return mapToAuthenticationResponse(jwtToken);
    }

    public User mapToUser(RegisterReq req){
        return User.builder()
                .firstName(req.getFirstNane())
                .lastName(req.getLastName())
                .email(req.getEmail())
                .password(passwordEncoder.encode(req.getPassword()))
                .role(Role.USER)
                .build();
    }

    public AuthenticationResp mapToAuthenticationResponse(String token){
        return AuthenticationResp.builder()
                .token(token)
                .build();
    }

}
