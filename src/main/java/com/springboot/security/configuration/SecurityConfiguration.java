package com.springboot.security.configuration;

import static com.springboot.security.configuration.ApplicationUserRole.STUDENT;

import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.springboot.security.auth.ApplicationUserService;
import com.springboot.security.jwt.JwtConfig;
import com.springboot.security.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import com.springboot.security.jwt.JwtVerifyTokenFilter;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration {

	private final PasswordEncoder passwordEncoder;
	private final ApplicationUserService applicationUserService;
	private final JwtConfig jwtConfig;
	private final SecretKey secretKey;
	
	
	@Autowired
	public SecurityConfiguration(PasswordEncoder passwordEncoder, 
								 ApplicationUserService applicationUserService, 
								 SecretKey secretKey, 
								 JwtConfig jwtConfig) {
		this.passwordEncoder = passwordEncoder;
		this.applicationUserService = applicationUserService;
		this.jwtConfig = jwtConfig;
		this.secretKey = secretKey;
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

		AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
		authenticationManagerBuilder
		.userDetailsService(applicationUserService)
		.passwordEncoder(passwordEncoder);
		
		AuthenticationManager authenticationManager = authenticationManagerBuilder. build();
		
        http
	        .csrf().disable()
	        .sessionManagement()
	        	.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
	        .and()
	        .authenticationManager(authenticationManager)
	        .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager, secretKey, jwtConfig))
	        .addFilterAfter(new JwtVerifyTokenFilter(secretKey, jwtConfig), JwtUsernameAndPasswordAuthenticationFilter.class)
	        .authorizeRequests()
	        .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
	        .antMatchers("/api/**").hasRole(STUDENT.name())
	//        .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
	//        .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
	//        .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
	//        .antMatchers("/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
	        .anyRequest()
		    .authenticated();
//	        .and()
//	//      .httpBasic();
//	        .formLogin()
//	        	.loginPage("/login")
//	        	.permitAll()
//	        	.usernameParameter("username")
//	        	.passwordParameter("password")
//	        .defaultSuccessUrl("/courses", true)
//	        .and()
//	        .rememberMe()
//	        	.tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))
//	        	.key("somethingverysecure")
//	        	.rememberMeParameter("remember-me")
//	        .and()
//	        .logout()
//	        	.logoutUrl("/logout")
//	        	.logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
//	        	.clearAuthentication(true)
//	        	.invalidateHttpSession(true)
//	        	.deleteCookies("JSESSIONID" , "remember-me")
//	        	.logoutSuccessUrl("/login");

		return http.build();

	}

	
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
			throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}
	
	
//	  @Bean
//	    public WebSecurityCustomizer webSecurityCustomizer() {
//	        return (web) -> web.ignoring().antMatchers("/", "/index");
//	    }

	
//	@Bean
//	public InMemoryUserDetailsManager userDetailsService() {
//		UserDetails user = User.builder()
//				.username("stguad")
//				.password(passwordEncoder.encode("password"))
////				.roles(STUDENT.name())
//				.authorities(STUDENT.getGrantedAuthorities())
//				.build();
//		
//		UserDetails userAdmin = User.builder()
//				.username("alex")
//				.password(passwordEncoder.encode("password123"))
////				.roles(ADMIN.name())
//				.authorities(ADMIN.getGrantedAuthorities())
//				.build();
//		
//		UserDetails userAdminTrainee = User.builder()
//				.username("rips")
//				.password(passwordEncoder.encode("password123"))
////				.roles(ADMINTRAINEE.name())
//				.authorities(ADMINTRAINEE.getGrantedAuthorities())
//				.build();
//
//		return new InMemoryUserDetailsManager(user, userAdmin, userAdminTrainee);
//	}

}
