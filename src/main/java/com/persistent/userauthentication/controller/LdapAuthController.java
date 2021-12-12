package com.persistent.userauthentication.controller;

import com.persistent.userauthentication.model.AuthenticationResponse;
import com.persistent.userauthentication.util.ldapauth.JwtTokenProvider;
import com.persistent.userauthentication.util.ldapauth.LdapAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/ldap")
public class LdapAuthController
{
    private static final String USER_DISABLED = "USER DISABLED";
    private static final String INVALID_CREDENTIALS = "INVALID CREDENTIALS";

    @Autowired
    private LdapAuthenticationProvider authenticationProvider;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Value("${access.token.life.time}")
    private Integer accessTokenLifeTime;

    @Value("${refresh.token.life.time}")
    private Integer refreshTokenLifeTime;

    @RequestMapping(value = "/auth-server", method = RequestMethod.POST)
    public ResponseEntity<?> authenticateRequest() throws Exception{

        authenticate(SecurityContextHolder.getContext().getAuthentication());

        final AuthenticationResponse accessToken = new AuthenticationResponse(JwtTokenProvider.generateToken(SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString()));
        final AuthenticationResponse refreshToken = new AuthenticationResponse(JwtTokenProvider.generateToken(SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString()));

        Map<String, AuthenticationResponse> tokens = new HashMap<>();
        tokens.put("access_token", accessToken);
        tokens.put("refresh_token", refreshToken);
        return ResponseEntity.ok(tokens);
    }

    private void authenticate(Authentication auth) throws Exception {
        try {
            authenticationProvider.authenticate(auth);
        } catch (DisabledException e) {
            throw new Exception(USER_DISABLED, e);
        } catch (BadCredentialsException e) {
            throw new Exception(INVALID_CREDENTIALS, e);
        }
    }

}
