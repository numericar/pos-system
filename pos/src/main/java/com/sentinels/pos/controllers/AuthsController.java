package com.sentinels.pos.controllers;

import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.sentinels.pos.dtos.requests.LoginRqDto;
import com.sentinels.pos.dtos.requests.RegisterRqDto;
import com.sentinels.pos.dtos.responses.AuthRsDto;
import com.sentinels.pos.dtos.responses.BaseResponseDto;
import com.sentinels.pos.entities.User;
import com.sentinels.pos.enums.UserRole;
import com.sentinels.pos.exceptions.UserException;
import com.sentinels.pos.securities.JwtProvider;
import com.sentinels.pos.services.interfaces.UserService;

@RestController
@RequestMapping("/api/auths")
public class AuthsController {

    private final UserService userService;

    public AuthsController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<BaseResponseDto<String>> register(@RequestBody RegisterRqDto dto) {
        try {
            if (this.userService.emailIsExists(dto.getEmail())) {
                throw new UserException("Email is already");
            }

            if (dto.getRole().equals(UserRole.ROLE_ADMIN)) {
                throw new UserException("Role admin is not allowed");
            }

            this.userService.createUser(dto);

            BaseResponseDto<String> rs = new BaseResponseDto<>(true, "Successful", null);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(rs);
        } catch (UserException ex) {
            BaseResponseDto<String> rs = new BaseResponseDto<>(false, ex.getMessage(), null);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(rs);
        } catch (Exception ex) {
            BaseResponseDto<String> rs = new BaseResponseDto<>(false, ex.getMessage(), null);
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(rs);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<BaseResponseDto<AuthRsDto>> login(@RequestBody LoginRqDto dto) {
        try {
            if (!this.userService.emailIsExists(dto.getEmail())) {
                throw new BadCredentialsException("Email or Password is invalid");
            }

            Optional<User> userOptional = this.userService.findByEmail(dto.getEmail());
            if (userOptional.isEmpty()) {
                throw new UserException("User not found");
            }
            User user = userOptional.get();

            if (!this.userService.isPasswordMatches(dto.getPassword(), user.getPassword())) {
                throw new BadCredentialsException("Email or Password is invalid");
            }

            String jwtToken = this.userService.generateToken(user);

            AuthRsDto authRsDto = new AuthRsDto();
            authRsDto.setJwt(jwtToken);

            BaseResponseDto<AuthRsDto> rs = new BaseResponseDto<>(true, "Successful", authRsDto);
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(rs);
        } catch (UserException ex) {
            BaseResponseDto<AuthRsDto> rs = new BaseResponseDto<>(false, ex.getMessage(), null);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(rs);
        } catch (BadCredentialsException ex) {
            BaseResponseDto<AuthRsDto> rs = new BaseResponseDto<>(false, ex.getMessage(), null);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(rs);
        } catch (Exception ex) {
            BaseResponseDto<AuthRsDto> rs = new BaseResponseDto<>(false, ex.getMessage(), null);
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(rs);
        }
    }
}
