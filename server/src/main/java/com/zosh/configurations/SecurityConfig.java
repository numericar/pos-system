package com.zosh.configurations;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import com.zosh.filters.JwtValidatorFilter;

import io.jsonwebtoken.lang.Arrays;
import jakarta.servlet.http.HttpServletRequest;

@Configuration
public class SecurityConfig {

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		HttpSecurity httpSecurity = http
				.sessionManagement(management -> management.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.authorizeHttpRequests(authorize -> authorize
						.requestMatchers("/api/**").authenticated() // /api/** จะต้องได้รับการยืนยันตัวตนก่อนใช้งาน
						.requestMatchers("/api/super-admin/**").hasRole("ADMIN").anyRequest().permitAll() // /api/super-admin/** จะต้องเป็นผู้ที่มีสิทธิ์ ADMIN เท่านั้น จึงจะใช้งานได้
				).addFilterBefore(new JwtValidatorFilter(), BasicAuthenticationFilter.class) // ทำการ filter ข้อมูลก่อนจะส่งต่อไปที่ apiโดยจะทำการตรวจสอบความถูกต้องของ JWT Toke new JwtValidator()
				.csrf(AbstractHttpConfigurer::disable) // ปิดการตรวจสอบ csrf
				.cors(cors -> cors.configurationSource(corsConfigurationSource())); // ตั้งค่า cors

		return httpSecurity.build();
	}

	private CorsConfigurationSource corsConfigurationSource() { // กำหนดการตั้งค่า cors เพื่อระบุว่า ใครสามารถเข้าถึง resource ได้บ้าง
		return new CorsConfigurationSource() {
			
			@Override
			public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
				List<String> originAlloweds = new ArrayList<>(); // ระบุว่าจะให้ domain อะไรร้องขอข้อมูลได้บ้าง
				originAlloweds.add("http://localhost:3000/");
				originAlloweds.add("http://localhost:5173/");
				
				List<String> exposedHeaders = new ArrayList<>();
				exposedHeaders.add("Authorization");
				
				CorsConfiguration cfg = new CorsConfiguration();
				cfg.setAllowedOrigins(originAlloweds);
				cfg.setAllowedMethods(Collections.singletonList("*"));
				cfg.setAllowCredentials(true);
				cfg.setAllowedHeaders(Collections.singletonList("*"));
				cfg.setExposedHeaders(exposedHeaders);
				cfg.setMaxAge(3600L);
				
				return cfg;
			}
		};
	}

}
