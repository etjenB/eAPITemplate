package org.etjen.eAPITemplate.exception;

import lombok.Getter;

@Getter
public enum ExceptionEnums {
    ExceptionCode(100),
    MethodArgumentNotValidExceptionCode(101),
    CustomUnauthorizedExceptionCode(102),
    AccountLockedExceptionCode(103),
    JwtGenerationExceptionCode(104);

    private final int code;

    ExceptionEnums(int code) {
        this.code = code;
    }

}
