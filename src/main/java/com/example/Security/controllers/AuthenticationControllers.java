package com.example.Security.controllers;

import com.example.Security.dto.AuthReq;
import com.example.Security.dto.AuthenticationResp;
import com.example.Security.dto.RegisterReq;
import com.example.Security.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthenticationControllers {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResp> register(@RequestBody RegisterReq request){
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResp> authenticate(@RequestBody AuthReq request){
        return ResponseEntity.ok(authService.authenticate(request));
    }
}
