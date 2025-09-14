package com.zosh.filters;

import java.io.IOException;
import java.util.List;

import javax.crypto.SecretKey;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.zosh.constants.JwtConstant;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtValidatorFilter extends OncePerRequestFilter { // OncePerRequestFilter ทำให้ filter นี้ถูกเรียกเพียงครั้งเดียว

	// doFilterInternal เป็น method หลักที่จะถูกเขียน logic การทำงานของ filter
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String jwt = request.getHeader(JwtConstant.JWT_HEADER); // ดึงข้อมูลของ authorization ที่ถูกส่งมากับ header
		
		if (jwt != null) {
			jwt = jwt.substring(7); // Bearer xxxxx, ตัดคำว่า bearer ออกจาก token
			
			try {
				SecretKey key = Keys.hmacShaKeyFor(JwtConstant.JWT_SECRET.getBytes()); // สร้าง key สำหรับตรวจสอบ jwt (private key)
				Claims claims = Jwts
						.parser()
						.verifyWith(key) // ตรวจสอบว่า jwt มีรายเซ็นถูกต้อง (เช็คกับ key ที่เป็น private key)
						.build()
						.parseSignedClaims(jwt) // แปรง token ออกมาเป็น claims
						.getPayload(); // ดึงข้อมูลที่อยู่ใน payload เช่น email, authorities
				
				String email = String.valueOf(claims.get("email")); // ดึงข้อมูล email
				String authorities = String.valueOf(claims.get("authorities")); // ดึงข้อมูล authorities (ROLE_USER,ROLE_ADMIN)
				
				// Spring Security จะใช้ GrantedAuthority ในการตรวจสอบสิทธิ์
				// AuthorityUtils.commaSeparatedStringToAuthorityList ทำหน้าที่แปรงข้อมูลสิทธิ์ที่เป็น array ไปเป็น GrantedAuthority
				// เช่น "ROLE_USER,ROLE_ADMIN" -> GrantedAuthority[] = ["ROLE_USER", "ROLE_ADMIN"]
				List<GrantedAuthority> grantedAuthorities = AuthorityUtils.commaSeparatedStringToAuthorityList(authorities);
				
				// UsernamePasswordAuthenticationToken เป็นคลาสที่จัดเก็บข้อมูลของผู้ใช้ที่ทำการ login แล้ว 
				// โดยแบ่งเป็น principal(username), credential(password), GrantedAuthority(roles)
				UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(email, null, grantedAuthorities);
				
				// นำข้อมูลของผู้ใช้ บันทึกลงใน context ของ spring security
				// โดยเป็นการบอก spring security ว่า request นี้ผู้ใช้ทำการ authenticate แล้ว
				// หลังจากนี้ controller, service จะสามารถเข้าถึงข้อมูลของผู้ที่ authenticate ได้ ผ่าน SecurityContextHolder.getContext().getAuthentication()
				SecurityContextHolder.getContext().setAuthentication(auth);
				
			} catch (Exception e) {
				// ถ้า JWT ไม่ถูกต้อง จะส่งคืน bad credential
				throw new BadCredentialsException("Invalid JWT");
			}
		}
		
		// หลังจากตรวจสอบเสร็จ ให้ filter ถ้ดไปทำงานต่อได้
		filterChain.doFilter(request, response);
	}

}
