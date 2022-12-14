package com.springboot.security.jwt;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.google.common.base.Strings;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

public class JwtVerifyTokenFilter extends OncePerRequestFilter {

	
	private final JwtConfig jwtConfig;
	private final SecretKey secretKey;
	
	public JwtVerifyTokenFilter(SecretKey secretKey, JwtConfig jwtConfig) {
		this.jwtConfig = jwtConfig;
		this.secretKey = secretKey;
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, 
									HttpServletResponse 
									response, 
									FilterChain filterChain)
			throws ServletException, IOException {

		String authorizationHeader = request.getHeader(jwtConfig.getAuthorizationHeader());
		
		if (Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith(jwtConfig.getTokenPrefix())) {
			filterChain.doFilter(request, response);
			return;
		}
		

		String token = authorizationHeader.replace(jwtConfig.getTokenPrefix(), "");
		
		try {
			

			
			Jws<Claims> claimsJws = Jwts.parserBuilder()
				.setSigningKey(secretKey)
				.build()
				.parseClaimsJws(token);
			
			Claims body = claimsJws.getBody();
			
			String subject = body.getSubject();
			
			var authorities = (List<Map<String, String>>) body.get("authorities");
			
			Set<SimpleGrantedAuthority> simpleGrantedAuthorities = authorities.stream()
			.map( a ->  new SimpleGrantedAuthority(a.get("authority")) )
			.collect(Collectors.toSet());
			
			
			Authentication authentication = new UsernamePasswordAuthenticationToken(
					subject, 
					null, 
					simpleGrantedAuthorities);
			
			SecurityContextHolder.getContext().setAuthentication(authentication);
			
			
		} catch (JwtException e) {
			throw new IllegalStateException(String.format("Token %s can't be trusted", token));
		}
		
		filterChain.doFilter(request, response);
	}

}
