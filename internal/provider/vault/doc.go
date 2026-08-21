// Package vault is a placeholder for provider 4: arbitrary leased secrets
// from an external secret store (Vault, or a cloud secrets manager).
// Designed in section 4.4 of the design doc as the lowest-priority
// provider -- "maybe never" built.
//
// Blunt honesty, straight from the design doc: this is External Secrets
// Operator's entire job, and ESO is a mature, widely-adopted CNCF project.
// Building this provider is the least defensible of the four, because "why
// not just use ESO" has no good answer for a portfolio project. It exists
// here only to show the Provider interface generalizes this far too.
//
// Recommendation (design doc section 4.4): do not build this one. If you
// build three providers ever, make them GitHub, AWS, and Database, and
// leave this package exactly as it is -- a documented note that the
// interface would support it.
package vault
