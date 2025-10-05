package com.sentinels.pos.services.impl;

import java.time.LocalDateTime;
import java.util.Optional;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.sentinels.pos.dtos.requests.RegisterRqDto;
import com.sentinels.pos.entities.User;
import com.sentinels.pos.repositories.UserRepository;
import com.sentinels.pos.securities.JwtProvider;
import com.sentinels.pos.services.interfaces.UserService;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;
    private final UserDetailsService userDetailsService;

    @Override
    public boolean emailIsExists(String email) {
        return this.userRepository.existsByEmail(email);
    }

    @Override
    public void createUser(RegisterRqDto registerDto) {
        LocalDateTime currentDateTime = LocalDateTime.now();

        User newUser = new User();
        newUser.setEmail(registerDto.getEmail());
        newUser.setPassword(this.passwordEncoder.encode(registerDto.getPassword()));
        newUser.setRole(registerDto.getRole());
        newUser.setFullName(registerDto.getFullName());
        newUser.setPhone(registerDto.getPhone());
        newUser.setCreatedAt(currentDateTime);
        newUser.setUpdatedAt(currentDateTime);

        this.userRepository.save(newUser);
    }

    @Override
    public boolean isPasswordMatches(String rawPassword, String passwordHashed) {
        return this.passwordEncoder.matches(rawPassword, passwordHashed);
    }

    @Override
    public Optional<User> findByEmail(String email) {
        return this.userRepository.findByEmail(email);
    }

    @Transactional
    @Override
    public String generateToken(User user) {
        this.userRepository.updateLastLoginAt(user.getId(), LocalDateTime.now());
        return this.jwtProvider.generateToken(authenticate(user.getEmail(), user.getPassword()));
    }

    private Authentication authenticate(String email, String password) {
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(email);
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }
}
