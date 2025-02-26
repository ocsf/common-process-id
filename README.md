# Common Process Identifier (CPID)

The Common Process Identifier (CPID pronounced "see-pid") enables endpoint software implementations to produce the same unique process identifier values without requiring synchronization or communication.

As a motivating example, consider an incident responder joining two endpoint datasets to understand endpoint process behavior.
Each dataset has its own unique process identifier scheme, but these identifiers are not compatible with each other.
Instead, the incident responder needs to rely on other process-identifying information:
- endpoint hostname (e.g. `BLDG001-M01`)
- operating system process identifier (e.g. `34534`)
- process creation time (e.g. `11/01/2024 14:40:47`)

Joining endpoint datasets in this manner is painful:
- These fields can be fragmented across different data points
- Hostname is often subject to misconfiguration or manipulation
- Process creation time is reported in different time formats and resolutions
- Operating system process identifiers are small numbers reused across time

With CPIDs, the incident responder only needs to join on an [RFC 9562](https://datatracker.ietf.org/doc/html/rfc9562) compliant UUID (e.g. `10eeaa35-0119-81d7-857a-9fed44d468e7`).  

## Specification

The written specification for CPID construction and statement of design goals is given in [specification.md](specification.md).

## Reference Implementations

This repository contains reference implementations for the CPID specification.
These implementations are given in directories named after their implementation language.
Each implementation contains its own README.md file for how to use the implementation.

These reference implementations can be used directly in security software or for asserting the correctness of custom implementations.
