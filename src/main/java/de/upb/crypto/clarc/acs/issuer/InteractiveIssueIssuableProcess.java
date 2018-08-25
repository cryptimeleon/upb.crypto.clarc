package de.upb.crypto.clarc.acs.issuer;

import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.IssuerKeyPair;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.IssueIssuableProtocolFactory;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Pseudonym;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.verifier.credentials.InteractiveVerificationProcess;
import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

/**
 * This will be used by the issuer for the receiveCredential/issueCredential protocol.
 */
public abstract class InteractiveIssueIssuableProcess<IssuableType extends Issuable,
        IssuedObject extends StandaloneRepresentable> extends InteractiveVerificationProcess {
    protected final PublicParameters pp;
    protected final IssuerKeyPair issuerKeyPair;
    protected final IssuableType issuable;
    protected final PedersenCommitmentValue uskCommitValue;

    protected IssueResponse<IssuedObject> issueResponse;

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
    public InteractiveIssueIssuableProcess(PublicParameters pp, IssuerKeyPair issuerKeyPair,
                                           Pseudonym pseudonym,
                                           PedersenCommitmentValue uskCommitValue,
                                           Announcement[] announcements, IssuableType issuable) {
        super(generateProtocol(pp, issuerKeyPair.getVerificationKey(), pseudonym, uskCommitValue),
                announcements);
        this.pp = pp;
        this.issuerKeyPair = issuerKeyPair;
        this.issuable = issuable;
        this.uskCommitValue = uskCommitValue;
    }

    /**
     * Builds the expressions for the proof of knowledge (the values for the witnesses are not set!!) and creates the
     * protocol used by the issuer.
     *
     * @param pp                    ACS public parameters
     * @param issuerVerificationKey Public verification key
     * @param pseudonym             Pseudonym from user
     * @param commitment            Commitment on the usk with parameters from issuer
     * @return The protocol needed to generate challenge
     */
    private static InteractiveThreeWayAoK generateProtocol(PublicParameters pp, PSExtendedVerificationKey
            issuerVerificationKey, Pseudonym pseudonym, PedersenCommitmentValue commitment) {
        IssueIssuableProtocolFactory protocolFactory = new IssueIssuableProtocolFactory(
                pp, issuerVerificationKey, pseudonym, commitment
        );
        return protocolFactory.getProtocol();
    }

    /**
     * Calculates the blinded signature/credential for the user
     *
     * @param responses The response of the user to the previously generated challenge
     * @return SignatureCredential with blinded signature
     */
    @Override
    public boolean verify(Response[] responses) {
        if (!super.verify(responses)) {
            issueResponse = null;
            return false;
        }

        return true;
    }

    public IssueResponse<IssuedObject> getIssueResponse() {
        return issueResponse;
    }
}
