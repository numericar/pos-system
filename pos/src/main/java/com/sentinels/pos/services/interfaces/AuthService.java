package com.sentinels.pos.services.interfaces;

import com.sentinels.pos.dtos.requests.LoginRqDto;
import com.sentinels.pos.dtos.requests.RegisterRqDto;
import com.sentinels.pos.exceptions.UserException;

public interface AuthService {
    void register(RegisterRqDto dto) throws UserException;
    String login(LoginRqDto dto) throws UserException;
}
