# Security Policy

## Reporting a vulnerability
Email security@csoai.org (or open a private security advisory). We aim to acknowledge within 72 hours.

## Scope
This MCP parses untrusted legacy/protocol input. It performs read-only parsing + governance classification; it does not execute, write to, or control source systems. SCADA/MQTT/CICS control actions are flagged for human authorisation, never executed.

## Supported versions
The latest released version on the default branch.
