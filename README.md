# Legacy
⚠️ This is upb.crypto legacy code, using outdated versions of our libraries. 

# upb.crypto.clarc
**WARNING: this implementation is meant to be used for prototyping and as a research tool *only*. It has not been sufficiently vetted to use in production.**

Cryptographic Library for Anonymous Reputation and Credentials

* acs: provides the actual implementation of CLARC (Cryptographic Library for Anonymous Reputation and Credentials). It contains the high-level actor classes which expose the functionality of the system in a consumer-friendly form.
This module is the API against which an user of the library should implement.

This upper layer in the architecture utilize lower-level libraries.
While the intended interface for applications consuming the library is CLARC, the other libraries can still be used in order to either, achieve greater control about the internals of the credential system, or also to reuse parts for completely credential system unrelated use-cases. For example, the commitment or signature schemes can be reused in a different context with this architecture.

## Installation

Clarc relies on old versions of the [Cryptimeleon Craco](https://github.com/cryptimeleon/craco) and [Cryptimeleon Math](https://github.com/cryptimeleon/math) library as well as our [legacy protocols](https://github.com/cryptimeleon/upb.crypto.protocols) library.
The required versions lie on the `fix-clarc-tests` branches on each of those github repositories.

You will need to check out that branch, build them via `./gradlew build` and then install them locally via `./gradlew publishToMavenLocal`, such that Clarc can use them, in this order:
1. Math
2. Craco
3. Protocols

Then you can do the same for Clarc itself and include it as a dependency.

## Further reading
Please see the workshop paper ["Fully-Featured Anonymous Credentials with Reputation System"](https://dl.acm.org/citation.cfm?id=3234517) (ARES 2018) and [the project group document](https://cs.uni-paderborn.de/fileadmin/informatik/fg/cuk/Lehre/Veranstaltungen/WS2016/ReACt/ReACt_documentation.pdf).

## Notes
CLARC was created within a project group called "Re(AC)^t" at Paderborn University in the working group ["Codes und Cryptography"](https://cs.uni-paderborn.de/en/cuk/research/).

## Licence
Apache License 2.0, see LICENCE file.
