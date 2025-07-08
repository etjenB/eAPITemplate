package org.etjen.eAPITemplate.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.etjen.eAPITemplate.exception.auth.AccountLockedException;
import org.etjen.eAPITemplate.exception.auth.ConcurrentSessionLimitException;
import org.etjen.eAPITemplate.exception.auth.CustomUnauthorizedException;
import org.etjen.eAPITemplate.exception.auth.UserNotFoundException;
import org.etjen.eAPITemplate.exception.auth.jwt.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestCookieException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import java.net.URI;

import static org.etjen.eAPITemplate.exception.ExceptionEnums.*;

/* ! In an effort to standardize REST API error handling, the IETF devised RFC 7807, which creates a generalized error-handling schema.

!    This schema is composed of five parts:

!    type – a URI identifier that categorizes the error
!    title – a brief, human-readable message about the error
!    status – the HTTP response code (optional)
!    detail – a human-readable explanation of the error
!    instance – a URI that identifies the specific occurrence of the error
!    Instead of using our custom error response body, we can convert our body:

!    {
!        "type": "/errors/incorrect-user-pass",
!        "title": "Incorrect username or password.",
!        "status": 401,
!        "detail": "Authentication failed due to incorrect username or password.",
!        "instance": "/login/log/abc123"
!    }

!    Note that the type field categorizes the type of error, while instance identifies a specific occurrence of the error in a similar fashion to classes and objects, respectively.
! */

@ControllerAdvice
public class GlobalExceptionHandler {
    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    // ? AUTH ----------------------------------------------------------------------------------------------------------------------------------------------------
    @ExceptionHandler(CustomUnauthorizedException.class)
    public ResponseEntity<ProblemDetail> handleCustomUnauthorizedExpection(CustomUnauthorizedException ex, HttpServletRequest request) {
        // Log as WARN (since it’s a client‐error/auth failure)
        logger.warn("Unauthorized attempt on [{}]: {}", request.getRequestURI(), ex.getMessage());
        ProblemDetail pd = ProblemDetail
                .forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        pd.setType(URI.create(request.getRequestURI()));
        pd.setTitle("Invalid login input");
        pd.setProperty("hostname", request.getHeader("Host"));
        pd.setProperty("code", CustomUnauthorizedException.code);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(pd);
    }

    @ExceptionHandler(AccountLockedException.class)
    public ResponseEntity<ProblemDetail> handleAccountLockedException(AccountLockedException ex, HttpServletRequest request) {
        logger.warn("Account is locked on [{}]: {}", request.getRequestURI(), ex.getMessage());
        ProblemDetail pd = ProblemDetail
                .forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        pd.setType(URI.create(request.getRequestURI()));
        pd.setTitle("Account is locked");
        pd.setProperty("hostname", request.getHeader("Host"));
        pd.setProperty("code", AccountLockedException.code);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(pd);
    }

    @ExceptionHandler(ConcurrentSessionLimitException.class)
    public ResponseEntity<ProblemDetail> handleConcurrentSessionLimitException(ConcurrentSessionLimitException ex, HttpServletRequest request) {
        logger.info("Concurrent sessions limit reached on [{}]: {}", request.getRequestURI(), ex.getMessage());
        ProblemDetail pd = ProblemDetail
                .forStatusAndDetail(HttpStatus.CONFLICT, ex.getMessage());
        pd.setType(URI.create(request.getRequestURI()));
        pd.setTitle("Concurrent sessions limit reached");
        pd.setProperty("hostname", request.getHeader("Host"));
        pd.setProperty("code", ConcurrentSessionLimitException.code);
        return ResponseEntity.status(HttpStatus.CONFLICT).body(pd);
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ProblemDetail> handleUserNotFoundException(UserNotFoundException ex, HttpServletRequest request) {
        logger.info("User not found on [{}]: {}", request.getRequestURI(), ex.getMessage());
        ProblemDetail pd = ProblemDetail
                .forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        pd.setType(URI.create(request.getRequestURI()));
        pd.setTitle("Invalid credentials");
        pd.setProperty("hostname", request.getHeader("Host"));
        pd.setProperty("code", UserNotFoundException.code);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(pd);
    }

    @ExceptionHandler(JwtGenerationException.class)
    public ResponseEntity<ProblemDetail> handleJwtGenerationException(JwtGenerationException ex, HttpServletRequest request) {
        logger.error("JWT generation exception on [{}]: {}", request.getRequestURI(), ex.getMessage());
        ProblemDetail pd = ProblemDetail
                .forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        pd.setType(URI.create(request.getRequestURI()));
        pd.setTitle("JWT generation exception");
        pd.setProperty("hostname", request.getHeader("Host"));
        pd.setProperty("code", JwtGenerationException.code);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(pd);
    }

    @ExceptionHandler(InvalidRefreshTokenException.class)
    public ResponseEntity<ProblemDetail> handleInvalidRefreshTokenExpection(InvalidRefreshTokenException ex, HttpServletRequest request) {
        logger.warn("Invalid refresh token expection on [{}]: {}", request.getRequestURI(), ex.getMessage());
        ProblemDetail pd = ProblemDetail
                .forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        pd.setType(URI.create(request.getRequestURI()));
        pd.setTitle("Invalid refresh token");
        pd.setProperty("hostname", request.getHeader("Host"));
        pd.setProperty("code", InvalidRefreshTokenException.code);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(pd);
    }

    @ExceptionHandler(RefreshTokenNotFoundException.class)
    public ResponseEntity<ProblemDetail> handleRefreshTokenNotFoundException(RefreshTokenNotFoundException ex, HttpServletRequest request) {
        logger.info("Refresh token was not found exception on [{}]: {}", request.getRequestURI(), ex.getMessage());
        ProblemDetail pd = ProblemDetail
                .forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
        pd.setType(URI.create(request.getRequestURI()));
        pd.setTitle("Refresh token was not found");
        pd.setProperty("hostname", request.getHeader("Host"));
        pd.setProperty("code", RefreshTokenNotFoundException.code);
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(pd);
    }

    @ExceptionHandler(RefreshTokensForUserNotFoundException.class)
    public ResponseEntity<ProblemDetail> handleRefreshTokensForUserNotFoundException(RefreshTokensForUserNotFoundException ex, HttpServletRequest request) {
        logger.info("Refresh tokens were not found exception on [{}]: {}", request.getRequestURI(), ex.getMessage());
        ProblemDetail pd = ProblemDetail
                .forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
        pd.setType(URI.create(request.getRequestURI()));
        pd.setTitle("Refresh tokens were not found");
        pd.setProperty("hostname", request.getHeader("Host"));
        pd.setProperty("code", RefreshTokensForUserNotFoundException.code);
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(pd);
    }

    @ExceptionHandler(ExpiredOrRevokedRefreshTokenException.class)
    public ResponseEntity<ProblemDetail> handleExpiredOrRevokedRefreshTokenExpection(ExpiredOrRevokedRefreshTokenException ex, HttpServletRequest request) {
        logger.warn("Expired or revoked refresh token expection on [{}]: {}", request.getRequestURI(), ex.getMessage());
        ProblemDetail pd = ProblemDetail
                .forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        pd.setType(URI.create(request.getRequestURI()));
        pd.setTitle("Expired or revoked refresh token");
        pd.setProperty("hostname", request.getHeader("Host"));
        pd.setProperty("code", ExpiredOrRevokedRefreshTokenException.code);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(pd);
    }

    @ExceptionHandler(AuthorizationDeniedException.class)
    public ResponseEntity<ProblemDetail> handleAuthorizationDeniedException(AuthorizationDeniedException ex, HttpServletRequest request) {
        logger.warn("Authorization denied expection on [{}]: {}", request.getRequestURI(), ex.getMessage());
        ProblemDetail pd = ProblemDetail
                .forStatusAndDetail(HttpStatus.FORBIDDEN, ex.getMessage());
        pd.setType(URI.create(request.getRequestURI()));
        pd.setTitle("User doesn't have a role to access this resource");
        pd.setProperty("hostname", request.getHeader("Host"));
        pd.setProperty("code", AuthorizationDeniedExceptionCode.getCode());
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(pd);
    }

    // ? SPRING VALIDATIONS ----------------------------------------------------------------------------------------------------------------------------------------------------

    @ExceptionHandler(MissingRequestCookieException.class)
    public ResponseEntity<ProblemDetail> handleMissingRequestCookieException(MissingRequestCookieException ex, HttpServletRequest request) {
        logger.warn("Invalid request, cookie was not provided by client on [{}]: {}", request.getRequestURI(), ex.getMessage());
        ProblemDetail pd = ProblemDetail
                .forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        pd.setType(URI.create(request.getRequestURI()));
        pd.setTitle("Cookie was not provided");
        pd.setProperty("hostname", request.getHeader("Host"));
        pd.setProperty("code", MissingRequestCookieExceptionCode.getCode());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(pd);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ProblemDetail> handleMethodArgumentNotValidException(MethodArgumentNotValidException ex, HttpServletRequest request) {
        logger.warn("Invalid request, validation failed on [{}]: {}", request.getRequestURI(), ex.getMessage());
        ProblemDetail pd = ProblemDetail
                .forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        pd.setType(URI.create(request.getRequestURI()));
        pd.setTitle("Invalid request");
        pd.setProperty("hostname", request.getHeader("Host"));
        pd.setProperty("code", MethodArgumentNotValidExceptionCode.getCode());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(pd);
    }

    // ? GLOBAL ----------------------------------------------------------------------------------------------------------------------------------------------------

    // * Fallback for anything else:
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleAllOthers(Exception ex, HttpServletRequest request) {
        ProblemDetail pd = ProblemDetail
                .forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
        pd.setType(URI.create(request.getRequestURI()));
        pd.setTitle("Unhandled exception");
        pd.setProperty("hostname", request.getHeader("Host"));
        pd.setProperty("code", ExceptionCode.getCode());
        // ! (Also log ex.stackTrace here)
        logger.error("Unhandled exception at [{}]", request.getRequestURI(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(pd);
    }
}
