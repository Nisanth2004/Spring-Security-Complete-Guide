package com.secure.notes.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/hello")
    public String hello()
    {
        return "Hello";
    }


    @GetMapping("/contact")
    public String contact()
    {
        return "Contact";
    }
}
