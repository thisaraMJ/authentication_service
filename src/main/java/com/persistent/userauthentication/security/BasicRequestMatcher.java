package com.persistent.userauthentication.security;

import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;

public class BasicRequestMatcher implements RequestMatcher {

    @Override
    public boolean matches(HttpServletRequest httpServletRequest) {
        return false;
    }

}
