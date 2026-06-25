package com.iqbalitsmy.users_api.config;

import com.iqbalitsmy.users_api.exception.AppExceptions;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.NoHandlerFoundException;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * ================================================================
 * STEP 16: GLOBAL EXCEPTION HANDLER
 * ================================================================
 * <p>
 * WHY @RestControllerAdvice?
 * Combines @ControllerAdvice + @ResponseBody.
 * Intercepts ALL exceptions thrown in any @RestController.
 * Converts them into clean, consistent JSON error responses.
 * <p>
 * Without this:
 * - Unhandled exceptions → Spring's "Whitelabel Error Page" (HTML)
 * - Stack traces may leak to clients → security risk
 * - Inconsistent error shapes confuse API consumers
 * <p>
 * DESIGN PRINCIPLE: AOP (Aspect-Oriented Programming)
 * Cross-cutting concerns (error handling) are separated from business logic.
 * Controllers don't know about HTTP error formatting — they just throw exceptions.
 * This handler intercepts them and shapes the response.
 * <p>
 * INTERVIEW TIP — "What HTTP status means what?"
 * 200 OK          → success
 * 201 Created     → resource created
 * 204 No Content  → success, nothing to return (DELETE)
 * 400 Bad Request → client sent invalid data (validation failure)
 * 401 Unauthorized → not authenticated (no/bad credentials or token)
 * 403 Forbidden   → authenticated but not authorised (wrong role)
 * 404 Not Found   → resource doesn't exist
 * 409 Conflict    → resource already exists (duplicate email)
 * 500 Internal    → unexpected server error (our bug)
 */
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {
    // ── VALIDATION (@Valid on @RequestBody) ───────────────────────
    /*
     * WHY: Thrown when @NotBlank, @Email, @Size etc. fail.
     * Collects ALL field errors and returns them together so the client
     * can fix all problems in one round-trip (not one error at a time).
     * HTTP 400 = client sent malformed/invalid data.
     */
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

    // ── ACCESS DENIED ─────────────────────────────────────────────
    /*
     * WHY 403 Forbidden?
     * User IS authenticated (valid JWT) but does NOT have the required role.
     * Example: ROLE_USER trying to call a ROLE_ADMIN endpoint.
     * INTERVIEW TIP: 401 = not authenticated. 403 = authenticated, not authorised.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> handleAccessDenied(
            AccessDeniedException ex) {
        log.warn("Access denied: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(buildBody(HttpStatus.FORBIDDEN,
                        "You do not have permission to perform this action"));
    }

    // ── NO HANDLER FOUND (route doesn't exist) ─────────────────────
    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<Map<String, Object>> handleNoHandlerFound(NoHandlerFoundException ex) {
        log.warn("No handler found for {} {}", ex.getHttpMethod(), ex.getRequestURL());
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(buildBody(HttpStatus.NOT_FOUND, "Route not found: " + ex.getRequestURL()));
    }

    // ── WRONG HTTP METHOD ON A VALID ROUTE ─────────────────────────
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<Map<String, Object>> handleMethodNotAllowed(HttpRequestMethodNotSupportedException ex) {
        log.warn("Method not allowed: {} on {}", ex.getMethod(), ex.getSupportedHttpMethods());
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED)
                .body(buildBody(HttpStatus.METHOD_NOT_ALLOWED,
                        "Method " + ex.getMethod() + " not supported for this route"));
    }

    // ── CATCH-ALL ─────────────────────────────────────────────────
    /*
     * WHY catch generic Exception?
     * Any uncaught exception would become a 500 with a stack trace in the response.
     * We catch everything, log the full stack server-side (for debugging),
     * and return a vague message to the client (never expose internals).
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGeneric(Exception ex) {
        log.error("Unexpected error: {}", ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(buildBody(HttpStatus.INTERNAL_SERVER_ERROR,
                        "An unexpected error occurred. Please try again later."));
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
