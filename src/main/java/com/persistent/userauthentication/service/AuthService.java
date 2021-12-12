package com.persistent.userauthentication.service;

import com.persistent.userauthentication.exception.UserNotFoundException;
import com.persistent.userauthentication.model.AuthenticationRequest;
import com.persistent.userauthentication.repository.AuthRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.Optional;

@Service("authService")
@Transactional
public class AuthService implements UserDetailsService {

    @Autowired
    private final AuthRepository authRepository;

    public AuthService(AuthRepository authRepository) {
        this.authRepository = authRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        AuthenticationRequest user = authRepository.findByUsername(userName);
        return new User( user.getUsername(), user.getPassword(), new ArrayList<>());
    }

    public AuthenticationRequest getUserByUsername(String userName){
        AuthenticationRequest user = authRepository.findByUsername(userName);
        return user;
    }

    public AuthenticationRequest findUserById(Long id) {
        return authRepository.findById(id)
                .orElseThrow(()->new UserNotFoundException("User is with id: "+id+"was not found!"));
    }

    public void updateSecretByUsername(String userName, String secret){
        AuthenticationRequest user = authRepository.findByUsername(userName);
        user.setSecret(secret);
        authRepository.save(user);
    }

}
