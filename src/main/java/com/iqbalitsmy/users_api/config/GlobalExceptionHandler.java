package com.iqbalitsmy.users_api.config;

import com.iqbalitsmy.users_api.exception.AppExceptions;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * WHY @RestControllerAdvice?
 * Combines @ControllerAdvice + @ResponseBody.
 * ControllerAdvice -> Intercepts ALL exceptions thrown in any @RestController.
 * ResponseBody -> Converts them into clean, consistent JSON error responses.
 *
 **/
@RestController
@Slf4j
public class GlobalExceptionHandler {
    // ── VALIDATION (@Valid on @RequestBody) ───────────────────────
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidation(MethodArgumentNotValidException ex) {
        Map<String, String> fieldError = ex.getBindingResult().getFieldErrors().stream().collect(Collectors.toMap(FieldError::getField, FieldError::getDefaultMessage, (first, second) -> first));
        log.warn("Validation failed: {}", fieldError);

        Map<String, Object> body = buildBody(HttpStatus.BAD_REQUEST, "Validation failed");

        body.put("errors", fieldError);

        return ResponseEntity.badRequest().body(body);
    }

    // ── RESOURCE NOT FOUND ────────────────────────────────────────
    @ExceptionHandler(AppExceptions.ResourceNotFoundException.class)
    public ResponseEntity<Map<String, Object>> handleNotFound(AppExceptions.ResourceNotFoundException ex) {
        log.warn("not found: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(buildBody(HttpStatus.NOT_FOUND, ex.getMessage()));
    }

    // ── DUPLICATE RESOURCE ────────────────────────────────────────
    @ExceptionHandler(AppExceptions.DuplicateResource.class)
    public ResponseEntity<Map<String, Object>> handleDuplicate(AppExceptions.DuplicateResource ex) {
        log.warn("duplicate resource :{}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(buildBody(HttpStatus.CONFLICT, ex.getMessage()));
    }

    // ── INVALID CREDENTIALS (local login) ────────────────────────────────────────
    @ExceptionHandler(AppExceptions.InvalidCredentialException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidCredential(AppExceptions.InvalidCredentialException ex) {
        log.warn("Invalid Credentials :{}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(buildBody(HttpStatus.UNAUTHORIZED, ex.getMessage()));
    }

    // ── INVALID JWT ACCESS TOKEN ────────────────────────────────────────
    @ExceptionHandler(AppExceptions.InvalidTokenException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidToken(AppExceptions.InvalidTokenException ex) {
        log.warn("Invalid Token :{}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(buildBody(HttpStatus.UNAUTHORIZED, ex.getMessage()));
    }

    // ── REFRESH TOKEN ERROR ────────────────────────────────────────
    @ExceptionHandler(AppExceptions.InvalidTokenRefreshException.class)
    public ResponseEntity<Map<String, Object>> handleTokenRefresh(AppExceptions.InvalidTokenRefreshException ex) {
        log.warn("Invalid Token Refresh :{}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(buildBody(HttpStatus.UNAUTHORIZED, ex.getMessage()));
    }

    // ── OAUTH2 ERROR  ────────────────────────────────────────
    @ExceptionHandler(AppExceptions.OAuth2AuthenticationException.class)
    public ResponseEntity<Map<String, Object>> handleOAuth2Authentication(AppExceptions.OAuth2AuthenticationException ex) {
        log.warn("OAuth2 error :{}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(buildBody(HttpStatus.BAD_REQUEST, ex.getMessage()));
    }

    private Map<String, Object> buildBody(HttpStatus status, String message) {
        Map<String, Object> body = new HashMap<>();

        body.put("timestamp", LocalDateTime.now().toString());
        body.put("status", status.value());
        body.put("error", status.getReasonPhrase());
        body.put("message", message);
        return body;
    }
}
