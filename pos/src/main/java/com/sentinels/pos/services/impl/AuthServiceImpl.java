package com.sentinels.pos.services.impl;

import java.time.LocalDateTime;
import java.util.Optional;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.sentinels.pos.dtos.requests.LoginRqDto;
import com.sentinels.pos.dtos.requests.RegisterRqDto;
import com.sentinels.pos.entities.User;
import com.sentinels.pos.enums.UserRole;
import com.sentinels.pos.exceptions.UserException;
import com.sentinels.pos.repositories.UserRepository;
import com.sentinels.pos.securities.JwtProvider;
import com.sentinels.pos.services.interfaces.AuthService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider; 
    private final UserDetailsService userDetailsService;

    @Override
    public void register(RegisterRqDto dto) throws UserException {
        Optional<User> userOptional = this.userRepository.findByEmail(dto.getEmail());

        if (userOptional.isPresent()) {
            throw new UserException("Email already registered");
        }

        if (dto.getRole().equals(UserRole.ROLE_ADMIN)) {
            throw new UserException("Role admin is not allowed");
        }

        LocalDateTime currentDateTime = LocalDateTime.now();

        User newUser = new User();
        newUser.setEmail(dto.getEmail());
        newUser.setPassword(this.passwordEncoder.encode(dto.getPassword()));
        newUser.setRole(dto.getRole());
        newUser.setFullName(dto.getFullName());
        newUser.setPhone(dto.getPhone());
        newUser.setCreatedAt(currentDateTime);
        newUser.setUpdatedAt(currentDateTime);

        this.userRepository.save(newUser);
    }

    @Override
    public String login(LoginRqDto dto) throws UserException {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'login'");
    }

}
