package com.persistent.userauthentication.model;

import javax.persistence.*;

//@Entity( name = "user")
@Entity
@Table(name="users")
public class AuthenticationRequest {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name="id",nullable = false,updatable = false)
    private Long id;

    @Column(name="username")
    private String username;

    @Column(name="password")
    private String password;

    @Column(name="secret")
    private String secret;

    public AuthenticationRequest(String username, String password, String secret) {
        this.username = username;
        this.password = password;
        this.secret = secret;
    }

    public AuthenticationRequest() {}

    public long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getSecret() { return secret; }

    public void setSecret(String secret) { this.secret = secret; }
}
