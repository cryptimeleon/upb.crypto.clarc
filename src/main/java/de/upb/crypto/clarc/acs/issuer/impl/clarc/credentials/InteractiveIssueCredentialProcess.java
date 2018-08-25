package de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials;

import de.upb.crypto.clarc.acs.issuer.credentials.Attributes;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Pseudonym;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;

import static de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.CreateCredentialHelper.createBlindedCredential;

public class InteractiveIssueCredentialProcess
        extends de.upb.crypto.clarc.acs.issuer.credentials.InteractiveIssueCredentialProcess<Attributes, PSCredential> {

    private CredentialIssuerPublicIdentity issuerPublicIdentity;

    /**
     * Initializes the issue credential process with all needed parameters.
     *
     * @param pp                   ACS public parameters
     * @param issuerKeyPair        Verification/Signing key pair for the issuer
     * @param pseudonym            Commitment value of the pseudonym (commitment on usk)
     * @param uskCommitValue       Commitment on usk, this time with parameters from verification key
     * @param announcements        Generated announcements from the user
     * @param attributes           Attributes that needs to be signed
     * @param issuerPublicIdentity public identity of the issuer
     */
    public InteractiveIssueCredentialProcess(PublicParameters pp,
                                             IssuerKeyPair issuerKeyPair,
                                             Pseudonym pseudonym,
                                             PedersenCommitmentValue uskCommitValue,
                                             Announcement[] announcements,
                                             Attributes attributes,
                                             CredentialIssuerPublicIdentity issuerPublicIdentity) {
        super(pp, issuerKeyPair, pseudonym, uskCommitValue, announcements, attributes);
        this.issuerPublicIdentity = issuerPublicIdentity;
    }

    /**
     * Verifies the protocol and if that is successful, calculates the blinded signature/credential for the user
     *
     * @param responses The response of the user to the previously generated challenge
     * @return SignatureCredential with blinded signature
     */
    @Override
    public boolean verify(Response[] responses) {
        if (!super.verify(responses)) {
            return false;
        }
        this.issueResponse = new CredentialIssueResponse(createBlindedCredential(
                pp,
                issuable,
                issuerKeyPair,
                issuerPublicIdentity,
                uskCommitValue));
        return true;
    }


}
