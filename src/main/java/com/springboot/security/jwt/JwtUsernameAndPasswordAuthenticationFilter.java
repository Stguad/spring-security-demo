package com.springboot.security.jwt;

import java.io.IOException;
import java.time.LocalDate;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;

public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private final AuthenticationManager auth;
	private final JwtConfig jwtConfig;
	private final SecretKey secretKey;
	

	public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager, 
													  SecretKey secretKey, 
													  JwtConfig jwtConfig) {
		this.auth = authenticationManager;
		this.jwtConfig = jwtConfig;
		this.secretKey = secretKey;
	}

	
	/**
	 * This method validates the sent credentials 
	 */
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {

		try {
			var authenticationRequest = new ObjectMapper().readValue(request.getInputStream(),
					UsernameAndPasswordAuthenticationRequest.class);

			Authentication authentication = new UsernamePasswordAuthenticationToken(
					authenticationRequest.getUsername(),
					authenticationRequest.getPassword()
			);

			return auth.authenticate(authentication);

		} catch (IOException e) {
			throw new RuntimeException();
		}

	}
	
	/**
	 * This methods creates a token to send it to the client if the validation of credentials was successful
	 */
	@Override
	protected void successfulAuthentication(HttpServletRequest request, 
											HttpServletResponse response, 
											FilterChain chain,
			Authentication authentication) throws IOException, ServletException {
		
		
		String token = Jwts.builder()
				.setSubject(authentication.getName())
				.claim("authorities",authentication.getAuthorities())
				.setIssuedAt(new Date())
				.setExpiration(java.sql.Date.valueOf(LocalDate.now().plusDays(jwtConfig.getTokenExpirationAfterDays())))
				.signWith(secretKey)
				.compact();
		
		response.addHeader(jwtConfig.getAuthorizationHeader(), "Bearer " + token);

	}

	
	  
}
