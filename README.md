# upb.crypto.clarc
Cryptographic Library for Anonymous Reputation and Credentials

* acs: provides the actual implementation of CLARC (Cryptographic Library for Anonymous Reputation and Credentials). It contains the high-level actor classes which expose the functionality of the system in a consumer-friendly form.
This module the API against which an user of the library should implement.

This upper layer in the architecture utilize lower-level libraries.
While the intended interface for applications consuming the library is CLARC, the other libraries can still be used in order to either, achieve greater control about the internals of the credential system, or also to reuse parts for completely credential system unrelated use-cases. For example, the commitment or signature schemes can be reused in a different context with this architecture.

## Further reading
Please see the workshop paper ["Fully-Featured Anonymous Credentials with Reputation System"](https://dl.acm.org/citation.cfm?id=3234517) (ARES 2018) and the project group document.

## Notes
CLARC was created within a project group called "Re(AC)^t" at Paderborn University in the working group ["Codes und Cryptography"](https://cs.uni-paderborn.de/en/cuk/research/).

## Licence
Apache License 2.0, see LICENCE file.
