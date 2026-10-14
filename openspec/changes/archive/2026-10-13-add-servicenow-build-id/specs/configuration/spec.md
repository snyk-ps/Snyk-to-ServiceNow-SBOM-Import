## ADDED Requirements

### Requirement: Optional ServiceNow build ID configuration

The utility SHALL accept an optional ServiceNow build ID from the `BUILD_ID` environment variable and the `--buildid` command-line argument. When `--buildid` is present, its value MUST take precedence over `BUILD_ID`, including when the command-line value is explicitly empty. When `--buildid` is absent, the utility SHALL use `BUILD_ID` when set. A missing, empty, or whitespace-only effective value SHALL be treated as unavailable and MUST NOT cause configuration validation to fail.

#### Scenario: Neither build ID input is provided

- **WHEN** neither `BUILD_ID` nor `--buildid` is provided
- **THEN** configuration validation succeeds without an effective build ID

#### Scenario: Environment build ID is used

- **WHEN** `BUILD_ID` is non-empty and `--buildid` is absent
- **THEN** the effective build ID is the value of `BUILD_ID`

#### Scenario: Command-line build ID is used

- **WHEN** `--buildid` is provided with a non-empty value and `BUILD_ID` is absent
- **THEN** the effective build ID is the command-line value

#### Scenario: Command-line build ID overrides environment

- **WHEN** both `BUILD_ID` and a non-empty `--buildid` value are provided
- **THEN** the effective build ID is the command-line value

#### Scenario: Explicitly empty command-line value overrides environment

- **WHEN** `BUILD_ID` is non-empty and `--buildid` is explicitly provided with an empty value
- **THEN** the effective build ID is empty
- **AND** the environment value is not used

#### Scenario: Empty environment value is optional

- **WHEN** `BUILD_ID` is unset, empty, or whitespace-only and `--buildid` is absent
- **THEN** configuration validation succeeds without an effective build ID

#### Scenario: Existing ServiceNow requirement remains mandatory

- **WHEN** build ID configuration is missing or empty
- **THEN** `SNOW_BUSINESS_APPLICATION_ID` remains required and is validated using the existing rules
