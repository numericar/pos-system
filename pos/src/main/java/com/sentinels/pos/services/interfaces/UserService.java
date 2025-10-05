package com.sentinels.pos.services.interfaces;

import java.util.Optional;

import com.sentinels.pos.dtos.requests.RegisterRqDto;
import com.sentinels.pos.entities.User;

public interface UserService {
    boolean emailIsExists(String email);
    void createUser(RegisterRqDto registerDto);
    boolean isPasswordMatches(String password, String passwordHashed);
    Optional<User> findByEmail(String email);
    String generateToken(User user);
}
