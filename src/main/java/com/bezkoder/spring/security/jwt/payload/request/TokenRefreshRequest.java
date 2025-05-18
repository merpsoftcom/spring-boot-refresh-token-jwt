package com.bezkoder.spring.security.jwt.payload.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

@Getter
public class TokenRefreshRequest {
  @NotBlank
  private String refreshToken;
}
