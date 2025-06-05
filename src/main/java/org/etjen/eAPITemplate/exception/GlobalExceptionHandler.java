package org.etjen.eAPITemplate.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.etjen.eAPITemplate.exception.auth.CustomUnauthorizedExpection;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
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
*/

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(CustomUnauthorizedExpection.class)
    public ResponseEntity<ProblemDetail> handleInvalidInput(CustomUnauthorizedExpection ex, HttpServletRequest request) {
        ProblemDetail pd = ProblemDetail
                .forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        pd.setType(URI.create(request.getRequestURI()));
        pd.setTitle("Invalid login input");
        pd.setProperty("hostname", request.getHeader("Host"));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(pd);
    }

    // Fallback for anything else:
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleAllOthers(Exception ex, HttpServletRequest request) {
        ProblemDetail pd = ProblemDetail
                .forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
        pd.setType(URI.create(request.getRequestURI()));
        pd.setTitle("Invalid login input");
        pd.setProperty("hostname", request.getHeader("Host"));
        // ! (Also log ex.stackTrace here)
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(pd);
    }
}
