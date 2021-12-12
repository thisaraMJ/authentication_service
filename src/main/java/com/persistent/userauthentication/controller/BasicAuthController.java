package com.persistent.userauthentication.controller;

import com.persistent.userauthentication.model.AuthenticationRequest;
import com.persistent.userauthentication.model.AuthenticationResponse;
import com.persistent.userauthentication.service.AuthService;
import com.persistent.userauthentication.util.basicauth.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/jwt")
public class BasicAuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private AuthService authService;

    @Autowired
    private JwtUtil jwtTokenUtil;

    @Value("${access.token.life.time}")
    private Integer accessTokenLifeTime;

    @Value("${refresh.token.life.time}")
    private Integer refreshTokenLifeTime;

    @RequestMapping(value = "/hello", method = RequestMethod.GET)
    public String Hello(){
        return "jwt authentication successful!";
    }

    @RequestMapping(value = "/auth-server", method = RequestMethod.POST)
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword())
            );
        }catch (BadCredentialsException e){
            throw new Exception("Username or password is incorrect!", e);
        }

        final UserDetails userDetails = authService.loadUserByUsername(authenticationRequest.getUsername());

        AuthenticationResponse accessToken = new AuthenticationResponse(jwtTokenUtil.generateToken(userDetails,accessTokenLifeTime));
        AuthenticationResponse refreshToken = new AuthenticationResponse(jwtTokenUtil.generateToken(userDetails,refreshTokenLifeTime));

        Map<String, AuthenticationResponse> tokens = new HashMap<>();
        tokens.put("access_token", accessToken);
        tokens.put("refresh_token", refreshToken);

        return ResponseEntity.ok(tokens);
    }

    @RequestMapping(value = "/extend-token", method = RequestMethod.POST)
    public ResponseEntity<?> createNewAuthenticationToken(@RequestHeader("Authorization") String token) throws Exception {
        AuthenticationResponse accessToken = new AuthenticationResponse(jwtTokenUtil.extendToken(token, accessTokenLifeTime));

        Map<String, AuthenticationResponse> tokens = new HashMap<>();
        tokens.put("access_token", accessToken);

        return ResponseEntity.ok(tokens);
    }

    @RequestMapping(value = "/invalidate", method = RequestMethod.POST)
    public ResponseEntity<?> invalidateAuthenticationToken(@RequestHeader("Authorization") String token) throws Exception {
        jwtTokenUtil.invalidateToken(token);
        return ResponseEntity.ok("Invalidation Successful!");
    }

}
