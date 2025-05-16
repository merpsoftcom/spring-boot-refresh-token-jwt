package com.bezkoder.spring.security.jwt.advice;

import java.util.Date;

import com.bezkoder.spring.security.jwt.exception.StandardException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import com.bezkoder.spring.security.jwt.exception.TokenRefreshException;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(value = StandardException.class)
    public ResponseEntity<ErrorMessage> handleStandardException(StandardException ex, WebRequest request) {
        return ResponseEntity.status(ex.getHttpStatus()).body(new ErrorMessage(
            ex.getHttpStatus().value(),
            new Date(),
            ex.getMessage(),
            request.getDescription(false)
        ));
    }

    @ExceptionHandler(value = TokenRefreshException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ErrorMessage handleTokenRefreshException(TokenRefreshException ex, WebRequest request) {
        return new ErrorMessage(
            HttpStatus.FORBIDDEN.value(),
            new Date(),
            ex.getMessage(),
            request.getDescription(false));
    }

    @ExceptionHandler(value = Throwable.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ErrorMessage handleTokenRefreshException(Throwable ex, WebRequest request) {
        return new ErrorMessage(
            500,
            new Date(),
            ex.getMessage(),
            request.getDescription(false));
    }
}
