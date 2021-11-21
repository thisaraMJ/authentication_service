package com.persistent.userauthentication.repository;

import com.persistent.userauthentication.model.AuthenticationRequest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;


@Repository
public interface AuthRepository extends JpaRepository<AuthenticationRequest,Long> {

    AuthenticationRequest findByUsername(String username);

    Optional<AuthenticationRequest> findById(Long id);

}
