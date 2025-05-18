package com.bezkoder.spring.security.jwt.advice;

import com.bezkoder.spring.security.jwt.exception.StandardException;
import com.bezkoder.spring.security.jwt.exception.TokenRefreshException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.util.Date;

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

    @ExceptionHandler(value = MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorMessage> handleAccessDeniedException(MethodArgumentNotValidException ex, WebRequest request) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorMessage(
            HttpStatus.BAD_REQUEST.value(),
            new Date(),
            ex.getMessage(),
            request.getDescription(false)
        ));
    }

    @ExceptionHandler(value = AccessDeniedException.class)
    public ResponseEntity<ErrorMessage> handleAccessDeniedException(AccessDeniedException ex, WebRequest request) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ErrorMessage(
            HttpStatus.UNAUTHORIZED.value(),
            new Date(),
            ex.getMessage(),
            request.getDescription(false)
        ));
    }


    @ExceptionHandler(value = TokenRefreshException.class)
    public ResponseEntity<ErrorMessage> handleTokenRefreshException(TokenRefreshException ex, WebRequest request) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ErrorMessage(
            HttpStatus.FORBIDDEN.value(),
            new Date(),
            ex.getMessage(),
            request.getDescription(false)
        ));
    }

//    @ExceptionHandler(value = Throwable.class)
//    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
//    public ErrorMessage handleTokenRefreshException(Throwable ex, WebRequest request) {
//        return new ErrorMessage(
//            500,
//            new Date(),
//            ex.getMessage(),
//            request.getDescription(false));
//    }
}
