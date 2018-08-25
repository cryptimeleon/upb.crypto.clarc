package de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens;

import de.upb.crypto.clarc.acs.issuer.InteractiveIssueIssuableProcess;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.IssuerKeyPair;
import de.upb.crypto.clarc.acs.issuer.reviewtokens.HashOfItem;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Pseudonym;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;

import static de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens.CreateReviewTokenHelper.createBlindedReviewToken;

public class InteractiveIssueReviewTokenProcess
        extends InteractiveIssueIssuableProcess<HashOfItem, RepresentableReviewToken> {
    /**
     * Initializes the issue credential process with all needed parameters.
     *
     * @param pp             ACS public parameters
     * @param issuerKeyPair  Verification/Signing key pair for the issuer
     * @param pseudonym      Commitment value of the pseudonym (commitment on usk)
     * @param uskCommitValue Commitment on usk, this time with parameters from verification key
     * @param announcements  Generated announcements from the user
     * @param hashOfItem     Hash of item the user wants a review token for
     */
    public InteractiveIssueReviewTokenProcess(PublicParameters pp,
                                              IssuerKeyPair issuerKeyPair,
                                              Pseudonym pseudonym,
                                              PedersenCommitmentValue uskCommitValue,
                                              Announcement[] announcements,
                                              HashOfItem hashOfItem) {
        super(pp, issuerKeyPair, pseudonym, uskCommitValue, announcements, hashOfItem);
    }

    /**
     * Calculates the blinded reviewToken for the user
     *
     * @param responses The response of the user to the previously generated challenge
     * @return ReviewToken with blinded signature
     */
    @Override
    public boolean verify(Response[] responses) {
        if (!super.verify(responses)) {
            return false;
        }
        this.issueResponse = new ReviewTokenIssueResponse(createBlindedReviewToken(
                pp,
                issuable,
                issuerKeyPair,
                uskCommitValue));
        return true;
    }

    @Override
    public ReviewTokenIssueResponse getIssueResponse() {
        return ((ReviewTokenIssueResponse) issueResponse);
    }
}
