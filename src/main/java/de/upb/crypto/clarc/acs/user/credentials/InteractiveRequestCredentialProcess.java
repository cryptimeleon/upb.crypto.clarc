package de.upb.crypto.clarc.acs.user.credentials;

import de.upb.crypto.clarc.acs.issuer.Issuable;
import de.upb.crypto.clarc.acs.user.InteractiveIssuingContext;
import de.upb.crypto.clarc.acs.user.InteractiveRequestIssuableProcess;
import de.upb.crypto.clarc.acs.user.User;

public abstract class InteractiveRequestCredentialProcess<IssuableType extends Issuable,
        IssuedObject extends SignatureCredential>
        extends InteractiveRequestIssuableProcess<IssuableType, IssuedObject> {
    /**
     * Initializes the process of requesting a credential for the user with all needed parameters.
     *
     * @param data     {@link InteractiveIssuingContext} containing all information needed from the {@link User}
     * @param issuable The attributes the user wants to be signed
     */
    public InteractiveRequestCredentialProcess(InteractiveIssuingContext data, IssuableType issuable,
                                               CredentialIssuanceReceiver<IssuableType, IssuedObject> receiver) {
        super(data, null, issuable, receiver);
    }
}
