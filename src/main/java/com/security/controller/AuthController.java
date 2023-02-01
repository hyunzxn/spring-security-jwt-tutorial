package com.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
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

	// 토큰 만들어 주는 역할
	@PostMapping("/authenticate")
	public ResponseEntity<String> authenticate(@RequestBody AuthRequest request) {

		// 넘어오는 Request 값을 기반으로 Authentication을 만든다 -> 인증을 시킨다.
		authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

		final UserDetails user = userRepository.findUserByEmail(request.getEmail());
		if (user != null) {
			return ResponseEntity.ok().body(jwtUtils.generateToken(user)); // 토큰을 발급해준다.
		}
		return ResponseEntity.internalServerError().body("Some error Occurred");
	}
}
