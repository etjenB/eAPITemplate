package org.etjen.eAPITemplate.web.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/test", produces = "application/json")
public class TestController {

    @GetMapping("/public/{text}")
    public String publicTestEndpoint(@PathVariable String text){
        return "Test endpoint: " + text;
    }

    @GetMapping("/private/{text}")
    @PreAuthorize("hasRole('ADMIN')")
    public String privateTestEndpoint(@PathVariable String text){
        return "Test endpoint: " + text;
    }
}
