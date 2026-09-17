## ADDED Requirements

### Requirement: Leveled logging

The utility SHALL support the log levels ERROR, WARNING, INFO, DEBUG, and TRACE, selectable via `DEBUG_LEVEL` (default INFO). Log output SHALL include a timestamp, level, and message.

#### Scenario: Level filtering

- **WHEN** `DEBUG_LEVEL` is set to `INFO`
- **THEN** DEBUG and TRACE messages are suppressed and INFO/WARNING/ERROR messages are emitted

#### Scenario: TRACE detail

- **WHEN** `DEBUG_LEVEL` is set to `TRACE`
- **THEN** logs include request URL, query parameters, request headers (redacted), request body where appropriate, response status, response headers, response body, and timing information

### Requirement: Variable-level debugging

The utility SHALL provide a reusable debug utility that logs named variables and objects to simplify troubleshooting. It MUST expose `log_variable(name, value)` and `log_object(value)`. Collections SHALL be summarized (e.g. length/size) and objects SHALL be pretty-printed.

#### Scenario: Log a scalar variable

- **WHEN** `debug.log_variable("SNYK_PROJECT_ID", project_id)` is called at DEBUG level or lower
- **THEN** the utility emits a log line naming the variable and its (redacted if sensitive) value

#### Scenario: Summarize a collection

- **WHEN** `debug.log_variable("Payload Size", len(sbom))` or a headers dict is logged
- **THEN** the utility emits a concise summary rather than dumping raw contents

#### Scenario: Pretty-print an object

- **WHEN** `debug.log_object(response.json())` is called
- **THEN** the object is pretty-printed for readability

### Requirement: Secret redaction

The utility MUST never log sensitive values in cleartext. Tokens, passwords, and authorization headers SHALL be redacted in all log output regardless of level.

#### Scenario: Authorization header redacted

- **WHEN** request headers containing an `Authorization` value are logged
- **THEN** the value is masked (e.g. `Bearer *******************`)

#### Scenario: Token variable redacted

- **WHEN** a variable recognized as a secret (token/password) is logged
- **THEN** its value is masked and the real value never appears in output
