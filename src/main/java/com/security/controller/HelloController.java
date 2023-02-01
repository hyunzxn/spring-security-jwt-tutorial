package com.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/greetings")
public class HelloController {

	@GetMapping
	public ResponseEntity<String> hello() {
		return ResponseEntity.ok().body("Hello World");
	}

	@GetMapping("/goodbye")
	public ResponseEntity<String> goodBye() {
		return ResponseEntity.ok().body("Good Bye");
	}
}
