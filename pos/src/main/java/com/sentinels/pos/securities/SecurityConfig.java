package com.sentinels.pos.securities;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import com.sentinels.pos.filters.JwtValidatorFilter;

import jakarta.servlet.http.HttpServletRequest;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        HttpSecurity httpSecurity = http
            .sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(authorize -> {
                authorize.requestMatchers("/api/**").authenticated();
                authorize.requestMatchers("/api/super-admin/**").hasRole("ADMIN").anyRequest().authenticated();
            })
            .addFilterBefore(new JwtValidatorFilter(), BasicAuthenticationFilter.class)
            .csrf(AbstractHttpConfigurer::disable)
            .cors(cors -> cors.configurationSource(corsConfigurationSource()));

        return httpSecurity.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    private CorsConfigurationSource corsConfigurationSource() { // กำหนดการตั้งค่า cors เพื่อระบุว่า ใครสามารถเข้าถึง resource ได้บ้าง
        return new CorsConfigurationSource() {

            @Override
            public CorsConfiguration getCorsConfiguration(HttpServletRequest arg0) {
                List<String> originAlloweds = new ArrayList<>();
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
