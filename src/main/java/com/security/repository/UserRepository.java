package com.security.repository;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;

@Repository
public class UserRepository {

	private final static List<UserDetails> APPLICATION_USERS = Arrays.asList(
		new User("adminTest@gmail.com",
			"password",
			Collections.singleton(new SimpleGrantedAuthority("ROLE_ADMIN"))
		),
		new User("userTest@gmail.com",
			"password",
			Collections.singleton(new SimpleGrantedAuthority("ROLE_USER"))
		)
	);

	public UserDetails findUserByEmail(String email) {
		// 원래는 여기서 이렇게 Mock 데이터로 만들어 놓은 유저를 찾는게 아니라 실제 DB에 있는 User를 조회해서 가지고 오는거구나.
		return APPLICATION_USERS.stream()
			.filter(u -> u.getUsername().equals(email))
			.findFirst()
			.orElseThrow(() -> new UsernameNotFoundException("No user was found"));
	}
}
