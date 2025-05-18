package com.bezkoder.spring.security.jwt.payload.response;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class LoginSuccessResponse {
    private String token;
    private String refreshToken;
    private Long id;
    private String username;
    private String email;
    private List<String> roles;
    private boolean isMFAEnabled;
    private boolean isMFAEnrolled;
    private String MFAQRCode;
}
