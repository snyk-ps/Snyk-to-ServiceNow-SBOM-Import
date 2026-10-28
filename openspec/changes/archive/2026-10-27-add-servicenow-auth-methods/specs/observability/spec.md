## MODIFIED Requirements

### Requirement: Secret redaction

The utility MUST never log sensitive values in cleartext. Tokens, usernames used for ServiceNow Basic authentication, passwords, and complete authorization-header values SHALL be redacted in all log output regardless of level. Logs MAY preserve the non-secret authorization scheme name (`Bearer` or `Basic`) while masking its credential value.

#### Scenario: Bearer authorization header redacted

- **WHEN** request headers containing `Authorization: Bearer <token>` are logged
- **THEN** the token is replaced by the standard mask
- **AND** the real token never appears in output

#### Scenario: Basic authorization header redacted

- **WHEN** request headers containing `Authorization: Basic <encoded-credentials>` are logged
- **THEN** the encoded credentials are replaced by the standard mask
- **AND** neither the encoded nor decoded credentials appear in output

#### Scenario: Credential variable redacted

- **WHEN** a variable recognized as a token, Basic-authentication username, or password is logged
- **THEN** its value is masked and the real value never appears in output

#### Scenario: Authentication method remains diagnosable

- **WHEN** ServiceNow authentication configuration is logged
- **THEN** the selected `SNOW_AUTH_METHOD` value MAY be shown
- **AND** no associated credential value is shown
