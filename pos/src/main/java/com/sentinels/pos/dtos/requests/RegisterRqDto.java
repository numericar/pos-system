package com.sentinels.pos.dtos.requests;

import com.sentinels.pos.enums.UserRole;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRqDto {
    private String email;
    private String password;
    private UserRole role;
    private String fullName;
    private String phone;
}
