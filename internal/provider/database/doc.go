// Package database is a placeholder for provider 3: short-lived database
// users/passwords, designed but NOT built in v1.
//
// See design doc section 4.3 for the full specification. Summary: connect
// to the target database as an admin (itself a secret the controller
// holds -- a significant trust concentration, noted first in
// docs/THREAT_MODEL.md), CREATE USER with a generated password and the
// configured GRANTs on Mint, and DROP USER the old one after a new one is
// active on rotation/expiry. Revoke is implemented as DROP USER -- reliable
// revoke is the entire point of this provider.
//
// This is the hardest of the four providers because cleanup has to survive
// controller restarts: an orphaned database user is a security hole, so
// created users must be tracked durably (in the CR's status and/or a
// labeled record), not just in memory. Design doc section 4.3 explicitly
// calls this out as the reason it is provider 3, not provider 2 -- do not
// attempt it until the controller core (rotation, finalizers, status) is
// rock-solid against the github-app provider.
//
// Honest positioning: this is exactly HashiCorp Vault's dynamic-database-
// secrets feature. Vault is the incumbent and does this at production
// scale; this provider demonstrates the pattern, it does not compete with
// Vault. Testing this provider for real needs a live database in a
// container (testcontainers, or a kind-hosted Postgres) -- there is no
// honest way to mock the lifecycle.
package database
