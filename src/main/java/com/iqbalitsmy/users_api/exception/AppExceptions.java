package com.iqbalitsmy.users_api.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;
/**
 * ================================================================
 * STEP 5: CUSTOM EXCEPTIONS
 * ================================================================
 *
 * WHY custom exceptions over generic RuntimeException?
 *
 *  1. CLARITY   — ResourceNotFoundException is far more descriptive
 *                 than RuntimeException("User not found").
 *
 *  2. HTTP MAP  — @ResponseStatus binds the exception to an HTTP status.
 *                 When thrown from a controller/service, Spring returns
 *                 that status automatically without extra if-else logic.
 *
 *  3. HANDLING  — GlobalExceptionHandler catches each type specifically
 *                 and returns the right status + message shape.
 *
 * WHY RuntimeException (unchecked)?
 * Unchecked exceptions don't need to be declared in method signatures.
 * Application-level errors (not found, duplicate, bad auth) are typically
 * RuntimeExceptions — they represent programming / usage errors, not
 * recoverable conditions that callers must explicitly handle.
 */

public class AppExceptions {
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public static class ResourceNotFoundException extends RuntimeException {
        public ResourceNotFoundException(String msg) {
            super(msg);
        }
    }

    @ResponseStatus(HttpStatus.CONFLICT)
    public static class DuplicateResource extends RuntimeException {
        public DuplicateResource(String msg) {
            super(msg);
        }
    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public static class InvalidCredentialException extends RuntimeException {
        public InvalidCredentialException(String msg) {
            super(msg);
        }
    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public static class InvalidTokenException extends RuntimeException {
        public InvalidTokenException(String msg) {
            super(msg);
        }
    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public static class InvalidTokenRefreshException extends RuntimeException {
        public InvalidTokenRefreshException(String msg) {
            super(msg);
        }
    }
    /*
     * WHY 400 for OAuth2 auth exception?
     * This exception is thrown during the OAuth2 flow when something goes wrong
     * on the server side of the OAuth2 handshake (not necessarily a bad credential).
     * For example: the provider sent back an unexpected format, or our
     * OAuth2UserInfo extraction failed.
     * 400 = bad request / processing failure on our end.
     */
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public static class OAuth2AuthenticationException extends RuntimeException {
        public OAuth2AuthenticationException(String msg) {
            super(msg);
        }
    }
}
