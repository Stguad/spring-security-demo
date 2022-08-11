package com.springboot.security.auth;

import static com.springboot.security.configuration.ApplicationUserRole.ADMIN;
import static com.springboot.security.configuration.ApplicationUserRole.ADMINTRAINEE;
import static com.springboot.security.configuration.ApplicationUserRole.STUDENT;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import com.google.common.collect.Lists;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {

	private final PasswordEncoder passwordEncoder;
	
	@Autowired
	public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
		return getApplicationUsers()
				.stream()
				.filter(au -> username.equals(au.getUsername()))
				.findFirst();
	}
	
	private List<ApplicationUser> getApplicationUsers(){	
		
		List<ApplicationUser> applicationUsers = Lists.newArrayList(
				new ApplicationUser(
						ADMIN.getGrantedAuthorities(),
						passwordEncoder.encode("password"),
						"alex", 
						true, 
						true, 
						true, 
						true),
				
				new ApplicationUser(
						ADMINTRAINEE.getGrantedAuthorities(),
						passwordEncoder.encode("password"),
						"rips", 
						true, 
						true, 
						true, 
						true),
				
				new ApplicationUser(
						STUDENT.getGrantedAuthorities(),
						passwordEncoder.encode("password"),
						"steven", 
						true, 
						true, 
						true, 
						true)
		);
		
		return applicationUsers;
		
	}
}
