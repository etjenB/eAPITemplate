package org.etjen.eAPITemplate.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.etjen.eAPITemplate.exception.auth.AccountLockedException;
import org.etjen.eAPITemplate.exception.auth.CustomUnauthorizedExpection;
import org.etjen.eAPITemplate.exception.auth.jwt.JwtGenerationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import java.net.URI;

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
    @ExceptionHandler(CustomUnauthorizedExpection.class)
    public ResponseEntity<ProblemDetail> handleCustomUnauthorizedExpection(CustomUnauthorizedExpection ex, HttpServletRequest request) {
        // Log as WARN (since it’s a client‐error/auth failure)
        logger.warn("Unauthorized attempt on [{}]: {}", request.getRequestURI(), ex.getMessage());
        ProblemDetail pd = ProblemDetail
                .forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        pd.setType(URI.create(request.getRequestURI()));
        pd.setTitle("Invalid login input");
        pd.setProperty("hostname", request.getHeader("Host"));
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
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(pd);
    }

    // ? GLOBAL ----------------------------------------------------------------------------------------------------------------------------------------------------

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ProblemDetail> handleMethodArgumentNotValidException(MethodArgumentNotValidException ex, HttpServletRequest request) {
        logger.warn("Invalid request, validation failed on [{}]: {}", request.getRequestURI(), ex.getMessage());
        ProblemDetail pd = ProblemDetail
                .forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        pd.setType(URI.create(request.getRequestURI()));
        pd.setTitle("Invalid request");
        pd.setProperty("hostname", request.getHeader("Host"));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(pd);
    }

    // * Fallback for anything else:
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleAllOthers(Exception ex, HttpServletRequest request) {
        ProblemDetail pd = ProblemDetail
                .forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
        pd.setType(URI.create(request.getRequestURI()));
        pd.setTitle("Unhandled exception");
        pd.setProperty("hostname", request.getHeader("Host"));
        // ! (Also log ex.stackTrace here)
        logger.error("Unhandled exception at [{}]", request.getRequestURI(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(pd);
    }
}
