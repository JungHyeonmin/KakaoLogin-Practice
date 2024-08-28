package com.jhm.kakaologinpractice.metaro._core.utils;

import com.jhm.kakaologinpractice.metaro._core.error.ApplicationException;
import com.jhm.kakaologinpractice.metaro._core.error.ErrorCode;
import org.springframework.security.core.context.SecurityContextHolder;

public class SecurityUtils {

    public static Long getCurrentMemberId() {

        String name = SecurityContextHolder.getContext().getAuthentication().getName();

        if(name.equals("anonymousUser")) {
            throw new ApplicationException(ErrorCode.ANONYMOUS_USER);
        }

        return Long.parseLong(name);
    }
}
