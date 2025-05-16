package com.bezkoder.spring.security.jwt.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;
@Getter
public class StandardException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  HttpStatus httpStatus;
  public StandardException(HttpStatus httpStatus, String message) {
    super(message);
    this.httpStatus = httpStatus;
  }
}
