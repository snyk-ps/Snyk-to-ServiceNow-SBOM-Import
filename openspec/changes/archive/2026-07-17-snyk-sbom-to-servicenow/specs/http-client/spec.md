## ADDED Requirements

### Requirement: Reusable HTTP wrapper

The utility SHALL provide a reusable HTTP wrapper used by both the Snyk and ServiceNow clients. The wrapper MUST apply a request timeout, provide standardized error handling, log requests and responses (via the observability layer with redaction), and record request timing.

#### Scenario: Timeout applied

- **WHEN** an HTTP request is made through the wrapper
- **THEN** a timeout is enforced and a timed-out request raises a standardized error rather than hanging indefinitely

#### Scenario: Request and response logging

- **WHEN** a request is made at DEBUG or TRACE level
- **THEN** the wrapper logs the method, URL, redacted headers, and response status, plus elapsed time

### Requirement: Standardized HTTP error handling

The HTTP wrapper SHALL translate transport and HTTP-status failures into a consistent error type that carries the operation, URL, HTTP status, parsed error message, and a recommended next step when available.

#### Scenario: Non-2xx response

- **WHEN** a request returns a non-2xx status
- **THEN** the wrapper raises a standardized error containing operation, URL, status, and parsed message

#### Scenario: Malformed response body

- **WHEN** a response body cannot be parsed as expected
- **THEN** the wrapper raises a standardized error indicating a malformed response

### Requirement: Exit code mapping

The utility SHALL map failure categories to documented exit codes: 0 success, 1 configuration error, 2 authentication failure, 3 SBOM generation failure, 4 ServiceNow upload failure, and 5 unexpected exception.

#### Scenario: Unexpected exception

- **WHEN** an unhandled exception occurs outside the known failure categories
- **THEN** the utility terminates with exit code 5 and logs the error with context
