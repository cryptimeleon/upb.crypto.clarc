package de.upb.crypto.clarc.acs.user.impl.clarc;

import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.IssuerPublicIdentity;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Identity;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.user.User;
import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl.FiatShamirProof;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentPair;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;

/**
 * Data container for all information used during the issuance process by the {@link User}
 */
public class NonInteractiveIssuingContext extends IssuingContext {

    private final FiatShamirProof proof;

    /**
     * @param pp                       ACS public parameters
     * @param pedersenPublicParameters Public parameters of the issuer's the commitment scheme
     * @param issuerPublicIdentity     public identity of the issuer
     * @param usk                      User secret
     * @param identity                 The users identity
     * @param uskCommitPair            Commitment on the usk with issuer parameters from the issuer
     * @param proof                    non-interactive proof of knowledge over the user's known secrets needed for
     *                                 issuing
     */
    NonInteractiveIssuingContext(PublicParameters pp,
                                 PedersenPublicParameters pedersenPublicParameters,
                                 IssuerPublicIdentity issuerPublicIdentity,
                                 UserSecret usk, Identity identity,
                                 PedersenCommitmentPair uskCommitPair,
                                 FiatShamirProof proof) {
        super(pp, pedersenPublicParameters, issuerPublicIdentity, usk, identity, uskCommitPair);
        this.proof = proof;
    }

    FiatShamirProof getProof() {
        return proof;
    }

    @Override
    public InteractiveThreeWayAoK generateProtocol() {
        throw new UnsupportedOperationException("There is no protocol to execute during non-interactive issuance");
    }
}
