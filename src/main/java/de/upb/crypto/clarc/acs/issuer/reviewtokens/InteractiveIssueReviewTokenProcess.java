package de.upb.crypto.clarc.acs.issuer.reviewtokens;

import de.upb.crypto.clarc.acs.issuer.InteractiveIssueIssuableProcess;
import de.upb.crypto.clarc.acs.issuer.Issuable;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.IssuerKeyPair;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Pseudonym;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;

public abstract class InteractiveIssueReviewTokenProcess<IssuableType extends Issuable,
        IssuedObject extends RepresentableReviewToken>
        extends InteractiveIssueIssuableProcess<IssuableType, IssuedObject> {

    /**
     * Initializes the issue credential process with all needed parameters.
     *
     * @param pp             ACS public parameters
     * @param issuerKeyPair  Verification/Signing key pair for the issuer
     * @param pseudonym      Commitment value of the pseudonym (commitment on usk)
     * @param uskCommitValue Commitment on usk, this time with parameters from verification key
     * @param announcements  Generated announcements from the user
     * @param issuable       Issuable that needs to be signed
     */
    public InteractiveIssueReviewTokenProcess(PublicParameters pp,
                                              IssuerKeyPair issuerKeyPair,
                                              Pseudonym pseudonym,
                                              PedersenCommitmentValue uskCommitValue,
                                              Announcement[] announcements,
                                              IssuableType issuable) {
        super(pp, issuerKeyPair, pseudonym, uskCommitValue, announcements, issuable);
    }
}
