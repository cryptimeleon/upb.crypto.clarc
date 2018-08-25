package de.upb.crypto.clarc.acs.user.impl.clarc;

import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.IssuerPublicIdentity;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.RequestCredentialProtocolFactory;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Identity;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.user.InteractiveIssuingContext;
import de.upb.crypto.clarc.acs.user.User;
import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import de.upb.crypto.craco.commitment.interfaces.CommitmentValue;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentPair;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;

/**
 * Data container for all information used during the issuance process by the {@link User}
 */
public class IssuingContext implements InteractiveIssuingContext {
    private final PublicParameters pp;
    private final PedersenPublicParameters pedersenPublicParameters;
    private final IssuerPublicIdentity issuerPublicIdentity;
    private final UserSecret usk;
    private final Identity identity;
    private final PedersenCommitmentPair uskCommitPair;

    /**
     * @param pp                       ACS public parameters
     * @param pedersenPublicParameters Public parameters of the issuer's the commitment scheme
     * @param usk                      User secret
     * @param issuerPublicIdentity     public identity of the issuer
     * @param identity                 The users identity
     * @param uskCommitPair            Commitment on the usk with issuer parameters from the issuer
     */
    IssuingContext(PublicParameters pp,
                   PedersenPublicParameters pedersenPublicParameters,
                   IssuerPublicIdentity issuerPublicIdentity,
                   UserSecret usk,
                   Identity identity,
                   PedersenCommitmentPair uskCommitPair) {
        this.pp = pp;
        this.pedersenPublicParameters = pedersenPublicParameters;
        this.issuerPublicIdentity = issuerPublicIdentity;
        this.usk = usk;
        this.identity = identity;
        this.uskCommitPair = uskCommitPair;
    }

    public PublicParameters getPp() {
        return pp;
    }

    public IssuerPublicIdentity getIssuerPublicIdentity() {
        return issuerPublicIdentity;
    }

    public UserSecret getUsk() {
        return usk;
    }

    public Identity getIdentity() {
        return identity;
    }

    public PedersenCommitmentPair getUskCommitPair() {
        return uskCommitPair;
    }

    @Override
    public InteractiveThreeWayAoK generateProtocol() {
        RequestCredentialProtocolFactory protocolFactory =
                new RequestCredentialProtocolFactory(pedersenPublicParameters, identity, uskCommitPair,
                        pp, usk);
        return protocolFactory.getProtocol();
    }

    @Override
    public CommitmentValue getUskCommitmentValue() {
        return uskCommitPair.getCommitmentValue();
    }
}
