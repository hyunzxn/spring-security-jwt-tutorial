package com.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.security.config.JwtUtils;
import com.security.dto.AuthRequest;
import com.security.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

	private final AuthenticationManager authenticationManager;
	private final UserRepository userRepository;
	private final JwtUtils jwtUtils;

	@PostMapping("/authenticate")
	public ResponseEntity<String> authenticate(@RequestBody AuthRequest request) {
		authenticationManager.authenticate(
			new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
		);
		final UserDetails user = userRepository.findUserByEmail(request.getEmail());
		if (user != null) {
			return ResponseEntity.ok().body(jwtUtils.generateToken(user));
		}
		return ResponseEntity.internalServerError().body("Some error Occured");
	}
}
