package com.iqbalitsmy.users_api.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

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

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public static class OAuth2AuthenticationException extends RuntimeException {
        public OAuth2AuthenticationException(String msg) {
            super(msg);
        }
    }
}
