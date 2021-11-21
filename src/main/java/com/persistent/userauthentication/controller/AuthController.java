package com.persistent.userauthentication.controller;

import com.persistent.userauthentication.model.AuthenticationRequest;
import com.persistent.userauthentication.model.AuthenticationResponse;
import com.persistent.userauthentication.service.AuthService;
import com.persistent.userauthentication.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private AuthService authService;

    @Autowired
    private JwtUtil jwtTokenUtil;

    @RequestMapping(value = "/jwt/hello", method = RequestMethod.GET)
    public String Hello(){
        return "jwt auhentication successfull";
    }

    @RequestMapping(value = "/ldapauth/hello", method = RequestMethod.GET)
    public String LdapAuth(){
        return "ldap authentication successful!";
    }

    @RequestMapping(value = "/googleauth/hello", method = RequestMethod.GET)
    public String GooglAauth(){
        return "google authentication successful!";
    }

    @RequestMapping(value = "/jwt/authenticate", method = RequestMethod.POST)
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword())
            );
        }catch (BadCredentialsException e){
            throw new Exception("username or password is incorrect!", e);
        }

        final UserDetails userDetails = authService.loadUserByUsername(authenticationRequest.getUsername());

        final String jwt = jwtTokenUtil.generateToken(userDetails);

        return ResponseEntity.ok(new AuthenticationResponse(jwt));
    }

    @RequestMapping(value = "/jwt/extendtoken", method = RequestMethod.POST)
    public ResponseEntity<?> createNewAuthenticationToken(@RequestHeader("Authorization") String token) throws Exception {
        final String jwt = jwtTokenUtil.extendToken(token);
        return ResponseEntity.ok(new AuthenticationResponse(jwt));
    }

    @RequestMapping(value = "/jwt/invalidate", method = RequestMethod.POST)
    public ResponseEntity<?> invalidateAuthenticationToken(@RequestHeader("Authorization") String token) throws Exception {
        jwtTokenUtil.invalidateToken(token);
        return ResponseEntity.ok("Invalidation Successful!");
    }

}
