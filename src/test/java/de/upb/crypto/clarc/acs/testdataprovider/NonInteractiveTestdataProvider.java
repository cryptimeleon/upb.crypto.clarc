package de.upb.crypto.clarc.acs.testdataprovider;

import de.upb.crypto.clarc.acs.attributes.AttributeNameValuePair;
import de.upb.crypto.clarc.acs.issuer.credentials.Attributes;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.CredentialIssueResponse;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.CredentialIssuer;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens.ReviewTokenIssueResponse;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens.ReviewTokenIssuer;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.ProtocolParameters;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Identity;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.systemmanager.impl.clarc.JoinResponse;
import de.upb.crypto.clarc.acs.systemmanager.impl.clarc.SystemManager;
import de.upb.crypto.clarc.acs.user.impl.clarc.NonInteractiveJoinRequest;
import de.upb.crypto.clarc.acs.user.impl.clarc.NonInteractivePolicyProof;
import de.upb.crypto.clarc.acs.user.impl.clarc.User;
import de.upb.crypto.clarc.acs.user.impl.clarc.credentials.CredentialNonInteractiveResponseHandler;
import de.upb.crypto.clarc.acs.user.impl.clarc.reviewtoken.ReviewTokenNonInteractiveResponseHandler;
import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.FiatShamirHeuristic;
import de.upb.crypto.math.hash.impl.SHA256HashFunction;

import java.math.BigInteger;

public class NonInteractiveTestdataProvider {

    private final PublicParameters clarcPP;
    private final User clarcUser;
    private final Identity clarcIdentity;
    private final CredentialIssuer issuer;
    private final ReviewTokenIssuer reviewTokenIssuer;
    private final SystemManager systemManager;
    private final InteractiveThreeWayAoK policyProvingProtocol;
    private final ProtocolParameters clarcProtocolParameters;


    public NonInteractiveTestdataProvider(PublicParameters clarcPP,
                                          User clarcUser,
                                          Identity clarcIdentity,
                                          CredentialIssuer issuer,
                                          ReviewTokenIssuer reviewTokenIssuer,
                                          SystemManager systemManager,
                                          InteractiveThreeWayAoK policyProvingProtocol,
                                          ProtocolParameters clarcProtocolParameters) {
        this.clarcPP = clarcPP;
        this.clarcUser = clarcUser;
        this.clarcIdentity = clarcIdentity;
        this.issuer = issuer;
        this.reviewTokenIssuer = reviewTokenIssuer;
        this.systemManager = systemManager;
        this.policyProvingProtocol = policyProvingProtocol;
        this.clarcProtocolParameters = clarcProtocolParameters;
    }

    public NonInteractivePolicyProof getNonInteractivePolicyProof() {
        FiatShamirHeuristic fiatShamirHeuristic =
                new FiatShamirHeuristic(policyProvingProtocol, new SHA256HashFunction());
        return new NonInteractivePolicyProof(clarcProtocolParameters, fiatShamirHeuristic.prove(), null);
    }

    public CredentialNonInteractiveResponseHandler getNonInteractiveCredentialRequest() {
        return clarcUser
                .createNonInteractiveIssueCredentialRequest(issuer.getPublicIdentity(), clarcIdentity,
                        new Attributes(new AttributeNameValuePair[]{
                                IssuerTestdataProvider.AGE.createAttribute(BigInteger.valueOf(18)),
                                IssuerTestdataProvider.GENDER.createAttribute("m"),
                        })
                );
    }

    public CredentialIssueResponse getNonInteractiveCredentialResponse() {
        return issuer.issueNonInteractively(getNonInteractiveCredentialRequest().getRequest());
    }

    public ReviewTokenNonInteractiveResponseHandler getNonInteractiveReviewTokenRequest() {
        return clarcUser.createNonInteractiveIssueReviewTokenRequest(
                reviewTokenIssuer.getPublicIdentity(),
                clarcIdentity,
                "123".getBytes());
    }

    public ReviewTokenIssueResponse getNonInteractiveReviewTokenResponse() {
        return reviewTokenIssuer.issueNonInteractively(getNonInteractiveReviewTokenRequest().getRequest());
    }

    public NonInteractiveJoinRequest getNonInteractiveJoinRequest() {
        return clarcUser.createNonInteractiveJoinRequest(systemManager.getPublicIdentity());
    }

    public JoinResponse getNonInteractiveJoinResponse() {
        return systemManager.nonInteractiveJoinVerification(getNonInteractiveJoinRequest());
    }
}
