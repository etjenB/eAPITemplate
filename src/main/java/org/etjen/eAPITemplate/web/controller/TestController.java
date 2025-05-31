package org.etjen.eAPITemplate.web.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/auth/test/{text}")
    public String testEndpoint(@PathVariable String text){
        return "Test endpoint: " + text;
    }
}
