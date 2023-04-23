package com.example.jwtresource.controllers;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class HomeController {

    @GetMapping(value = "/", produces = {MediaType.TEXT_PLAIN_VALUE})
    public String home(Principal principal) {
        return "Hello, %s!".formatted(principal.getName());
    }
}
