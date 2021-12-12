package com.persistent.userauthentication.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/google")
public class OauthController {

    @RequestMapping(value = "/auth-server", method = RequestMethod.GET)
    public String GoogleAuth(){
        return "google authentication successful!";
    }

}
