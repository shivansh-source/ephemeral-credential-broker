# Threat model

This is a short, honest threat model, stated plainly rather than sold. If
you only read one document in this repo before deciding whether to trust
this controller with anything, read this one.

## What this defends against

- **Long-lived credential theft.** There is no long-lived credential
  sitting in the cluster to steal. Every credential an `EphemeralCredential`
  produces expires on a short TTL (for the v1 GitHub provider, GitHub's own
  ~1-hour installation-token lifetime).
- **Over-scoped access.** A credential is minted to exactly the scope
  declared in the CR (`spec.providerConfig.github.repositories` and
  `.permissions`), not a broad standing grant that happens to cover what one
  workload needs plus a lot it doesn't.
- **Credential sprawl.** Credentials are cleaned up on expiry and on
  `EphemeralCredential` deletion (via a finalizer); they do not quietly
  accumulate the way personal access tokens and static IAM keys tend to.
- **Coarse revocation.** Where the provider supports it (GitHub App
  installation tokens do, via `DELETE /installation/token`), a single
  credential can be invalidated without touching a user's whole session or
  a shared key used by other workloads too.

## What this does NOT defend against

State these as plainly as what's defended against -- this is the part a
sales pitch would bury.

- **Read access to the target Secret during the credential's lifetime.**
  The minted credential is plaintext in the target Kubernetes Secret for as
  long as it's valid. This project shrinks the exposure *window* (down to
  the TTL) and narrows the *blast radius* (down to one repo's read scope,
  say, instead of a whole personal access token) -- it does not make the
  Secret itself unreadable. Anything with `get`/`list`/`watch` on Secrets in
  that namespace during the credential's lifetime still gets a usable
  credential. Kubernetes Secrets are base64, not encryption, at rest by
  default; this project does not change that (see Non-goals below).
- **A compromised controller.** The controller holds the *minting*
  credential -- for the GitHub provider, the App's private key (referenced
  by `appConfigRef`). That private key can mint an installation token for
  every repository the App is installed on, with every permission the App
  itself has, at will. **Compromising the controller is strictly worse than
  compromising any single minted credential** -- this is the central risk of
  the whole design, and it is stated first, not buried at the end. Whoever
  can read the App's private key Secret, or exec into the controller's pod,
  or forge a request the controller will honor, has effectively unlimited
  minting power within the App's installed scope. Treat the controller's
  own RBAC (who can read Secrets in its namespace, who can exec into its
  pod, who can create/patch `EphemeralCredential` objects it will act on) as
  the highest-value surface in this whole system -- more sensitive than any
  Secret it ever writes.
- **A compromised provider.** If GitHub itself (or, for providers 2-4:
  AWS, the target database, or Vault) is compromised, this broker cannot
  help you. It is a thin client of whatever the provider does; it inherits
  the provider's own security properties and failure modes.
- **A misconfigured scope.** The broker mints exactly what the CR's
  `spec.providerConfig` asks for. If a workload owner writes an
  over-broad `permissions` block, they get an over-broad -- but still
  short-lived -- token. The broker does not second-guess or narrow what a
  CR asks for; it is not a policy engine, and does not pretend to be one.
  Kubernetes RBAC on who may create/edit `EphemeralCredential` objects is
  what should constrain this, the same as it constrains any other
  privileged-shaped resource.

## Trust boundaries

In descending order of what's actually at stake if compromised:

1. **The minting credential itself** -- the GitHub App's private key
   (`appConfigRef`), and in the not-yet-built providers, the controller's
   AWS IAM role or the database admin credential (see section 4 of the
   design doc). This is the crown jewel.
2. **The controller's own Kubernetes permissions** -- it can read the App
   key Secret, and can create/update/delete Secrets in any namespace it
   watches `EphemeralCredential` objects in.
3. **The provider's own API** (`api.github.com` for v1) -- outside this
   project's control entirely.
4. **Each individual minted credential** -- deliberately the least
   sensitive tier: short-lived, narrowly scoped, and (for GitHub)
   individually revocable.

## A note on honesty vs. selling

This capability -- short-lived, narrowly-scoped, auto-rotating credentials
instead of long-lived static ones -- is commoditized. Cloud providers ship
it for free specifically to make you stickier to their platform (AWS
IRSA / EKS Pod Identity, GKE Workload Identity, Azure Workload Identity),
and HashiCorp Vault's dynamic secrets engine does the database and
arbitrary-secret cases at production scale already. This project is not
better than those where they're available, and does not claim to be. Its
value is as a clean, honestly-scoped demonstration of the pattern and of
controller-runtime engineering -- not as a product anyone should adopt in
preference to a mature managed alternative that already covers their case.
