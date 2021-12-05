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

Clarc relies on old versions of the [Cryptimeleon Craco](https://github.com/cryptimeleon/craco/tree/fix-clarc-tests) and [Cryptimeleon Math](https://github.com/cryptimeleon/math/tree/fix-clarc-tests) library as well as our [legacy protocols](https://github.com/cryptimeleon/upb.crypto.protocols/tree/fix-clarc-tests) and [mclwrap](https://github.com/cryptimeleon/mclwrap/commit/6ce111a0821f32e184c75eb43230592689967255) library.
Their jars have been included in the `dependency-bin` dir, so no further action is needed.

If you want to run clarc with the fast mcl pairing, run the `install_mcl.sh` script (on Linux or Windows) or manually install [libmcljava v1.03](https://github.com/herumi/mcl/releases/tag/v1.03). If you do not do this, you will be stuck with the much slower java-based pairing.

We have committed a Dockerfile that sets up mcl and holds the clarc project in `/app`. You can run the (performance) tests via `./gradlew test`.

## Further reading
Please see the workshop paper ["Fully-Featured Anonymous Credentials with Reputation System"](https://dl.acm.org/citation.cfm?id=3234517) (ARES 2018) and [the project group document](https://cs.uni-paderborn.de/fileadmin/informatik/fg/cuk/Lehre/Veranstaltungen/WS2016/ReACt/ReACt_documentation.pdf).

## Notes
CLARC was created within a project group called "Re(AC)^t" at Paderborn University in the working group ["Codes und Cryptography"](https://cs.uni-paderborn.de/en/cuk/research/).

## Licence
Apache License 2.0, see LICENCE file.
