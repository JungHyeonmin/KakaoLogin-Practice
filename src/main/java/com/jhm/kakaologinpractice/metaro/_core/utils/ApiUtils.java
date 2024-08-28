package com.jhm.kakaologinpractice.metaro._core.utils;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

public class ApiUtils {

    public static <T> ApiResult<T> success(T response) {
        return new ApiResult<>(true, response, null);
    }

    public static <T> ApiResult<T> error(T data) {
        return new ApiResult<>(false, null, data);
    }

    @Getter
    @Setter
    @AllArgsConstructor
    public static class ApiResult<T> {
        private final boolean success;
        private final T response;
        private final T error;
    }
}
