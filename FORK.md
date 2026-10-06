# Fork maintenance scope

This fork maintains a bounded ASN.1 validation correction on top of
[digitalbazaar/forge](https://github.com/digitalbazaar/forge). It preserves the
upstream authors and licenses. No package release or downstream dependency
adoption is implied by this source branch.

The base is upstream commit
[683ab3344899cc08a581e4d5675a33e87aff7b04](https://github.com/digitalbazaar/forge/commit/683ab3344899cc08a581e4d5675a33e87aff7b04),
including the two original RSA DigestAlgorithm validation commits from
[upstream PR #1157](https://github.com/digitalbazaar/forge/pull/1157).
The fork correction rejects empty, nonminimal, unterminated and non-byte OID
encodings in the shared decoder. It correctly decodes the combined first
subidentifier and preserves binary-string and Forge buffer consumption.

Every encoded subidentifier remains bounded to 53 bits. For first arc 2,
the maximum supported second arc is therefore 9007199254740911.
The encoder's existing 32-bit limit is unchanged.

## Verification and limitations

Run python3 .github/ci/verify.py /absolute/path/to/fresh-results from a clean
committed checkout with Docker available. CI builds the committed source in a
digest-pinned Node 24 image, installs only separately locked Mocha 12.0.3 with
package scripts disabled, and fails on any tooling audit advisory. Tests run
without network access, with a read-only filesystem and an unprivileged user.

The gate runs the complete upstream Node suite and 25 encoding/security
compatibility controls. It requires the current 880 tests, at least 876 passes,
no failures and exactly the four existing deterministic RSA key-generation
skips. Those skips are caused by native Node key-generation availability;
they are reported, not counted as passes. The unchanged Ed25519 implementation
also emits Node's DEP0005 Buffer-constructor deprecation warning.

This scope does not establish browser compatibility, support for every Node
version advertised by upstream, a full cryptographic audit or suitability for
a particular application. Browser/Karma, legacy build dependencies and package
publication are outside this CI. Release and downstream consumption need their
own review. Follow the existing upstream security reporting policy for
vulnerability disclosures; report fork-specific maintenance issues here.
