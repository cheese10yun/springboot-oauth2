package com.example.oauth2;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SimpleController {

    @GetMapping("/api/session")
    public Authentication session() {
        return SecurityContextHolder.getContext().getAuthentication();
    }
}
