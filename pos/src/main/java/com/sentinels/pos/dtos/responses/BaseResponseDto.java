package com.sentinels.pos.dtos.responses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class BaseResponseDto<T> {
    private boolean isSuccess;
    private String message;
    private T data;
}
