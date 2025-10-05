package com.sentinels.pos.securities;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.SecretKey;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import com.sentinels.pos.constants.JwtConstant;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtProvider {

    private static SecretKey key = Keys.hmacShaKeyFor(JwtConstant.JWT_SECRET.getBytes());

    public String generateToken(Authentication authentication) {
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

        String authoritiesStr = extractAuthorities(authorities);
        LocalDateTime issuedAt = LocalDateTime.now();
        LocalDateTime expiration = issuedAt.plusDays(1);

        return Jwts
            .builder()
            .issuedAt(Date.from(issuedAt.atZone(ZoneId.of("Asia/Bangkok")).toInstant()))
            .expiration(Date.from(expiration.atZone(ZoneId.of("Asia/Bangkok")).toInstant()))
            .claim("email", authentication.getName())
            .claim("authorities", authoritiesStr)
            .signWith(key)
            .compact();
    }

    private String extractAuthorities(Collection<? extends GrantedAuthority> authorities) {
        Set<String> auths = new HashSet<>();
		for (GrantedAuthority authority : authorities) {
			auths.add(authority.getAuthority());
		}
		
		return String.join(",", auths);
    }

    public String getEmailFromToken(String token) {
        String jwt = token.substring(7);

        Claims claims = Jwts
            .parser()
            .verifyWith(key) // ตรวจสอบว่า jwt มีรายเซ็นถูกต้อง (เช็คกับ key ที่เป็น private key)
            .build()
            .parseSignedClaims(jwt) // แปรง token ออกมาเป็น claims
            .getPayload(); // ดึงข้อมูลที่อยู่ใน payload เช่น email, authorities
        
        return String.valueOf(claims.get("email"));
    }
}
