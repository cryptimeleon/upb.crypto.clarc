package de.upb.crypto.clarc.acs.user.impl.clarc;

import de.upb.crypto.clarc.protocols.fiatshamirtechnique.Proof;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;

public class NonInteractiveJoinRequest extends de.upb.crypto.clarc.acs.user.NonInteractiveJoinRequest {

    public NonInteractiveJoinRequest(Proof proof,
                                     GroupElement tau,
                                     UserPublicKey upk) {
        super(proof, tau, upk);
    }

    public NonInteractiveJoinRequest(Representation representation) {
        super(representation);
    }
}
