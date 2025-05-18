package com.bezkoder.spring.security.jwt.payload.response;

import lombok.Builder;
import lombok.Setter;

@Setter
@Builder
public class MfaVerificationResponse {
    private String username;
    private String jwt;
    private boolean mfaRequired;
    private boolean authValid;
    private boolean tokenValid;
    private String message;
}
