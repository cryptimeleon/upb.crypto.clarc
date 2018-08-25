package de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens;

import de.upb.crypto.clarc.acs.issuer.Issuer;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.IssuerKeyPair;
import de.upb.crypto.clarc.acs.issuer.reviewtokens.HashOfItem;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.IssueIssuableProtocolFactory;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Pseudonym;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.user.NonInteractiveIssuableRequest;
import de.upb.crypto.clarc.acs.user.impl.clarc.reviewtoken.NonInteractiveReviewTokenRequest;
import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.FiatShamirHeuristic;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.craco.commitment.interfaces.CommitmentValue;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.math.hash.impl.SHA256HashFunction;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.Objects;

public class ReviewTokenIssuer implements Issuer<HashOfItem, RepresentableReviewToken> {
    @Represented
    private PublicParameters pp;
    private IssuerKeyPair keyPair;
    @Represented
    private ReviewTokenIssuerPublicIdentity publicIdentity;


    public ReviewTokenIssuer(PublicParameters pp) {
        this.pp = pp;

        ReviewTokenIssuerKeyPairFactory factory = new ReviewTokenIssuerKeyPairFactory(pp);
        keyPair = factory.create();
        this.publicIdentity = new ReviewTokenIssuerPublicIdentity(keyPair.getVerificationKey());
    }

    public ReviewTokenIssuer(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
        Zp zp = pp.getZp();
        Group g1 = pp.getBilinearMap().getG1();
        Group g2 = pp.getBilinearMap().getG2();
        keyPair = new IssuerKeyPair(representation.obj().get("keyPair"), zp, g1, g2);
    }

    @Override
    public InteractiveIssueReviewTokenProcess initInteractiveIssueProcess(CommitmentValue commitment,
                                                                          de.upb.crypto.clarc.acs.pseudonym.Pseudonym pseudonym,
                                                                          HashOfItem issuable,
                                                                          Announcement[] announcements) {
        if (!(pseudonym instanceof Pseudonym)) {
            throw new IllegalArgumentException("Unsupported Pseudonym type!");
        }
        if (!(commitment instanceof PedersenCommitmentValue)) {
            throw new IllegalArgumentException("Unsupported Commitment type!");
        }
        return new InteractiveIssueReviewTokenProcess(pp, keyPair, (Pseudonym) pseudonym,
                (PedersenCommitmentValue) commitment, announcements, issuable);
    }

    @Override
    public ReviewTokenIssueResponse issueNonInteractively(
            NonInteractiveIssuableRequest<HashOfItem> nonInteractiveIssuableRequest) {
        if (!(nonInteractiveIssuableRequest instanceof NonInteractiveReviewTokenRequest)) {
            throw new IllegalArgumentException("Unsupported request type");
        }

        final NonInteractiveReviewTokenRequest clarcReviewTokenRequest =
                (NonInteractiveReviewTokenRequest) nonInteractiveIssuableRequest;
        IssueIssuableProtocolFactory protocolFactory = new IssueIssuableProtocolFactory(
                pp, keyPair.getVerificationKey(),
                clarcReviewTokenRequest.getPseudonym(),
                clarcReviewTokenRequest.getCommitment()
        );
        final InteractiveThreeWayAoK protocol = protocolFactory.getProtocol();
        FiatShamirHeuristic fiatShamirHeuristic = new FiatShamirHeuristic(protocol, new SHA256HashFunction());
        if (!fiatShamirHeuristic.verify(clarcReviewTokenRequest.getProof())) {
            return null;
        }
        RepresentableReviewToken token = CreateReviewTokenHelper.createBlindedReviewToken(pp,
                clarcReviewTokenRequest.getIssuable(), keyPair,
                clarcReviewTokenRequest.getCommitment());
        return new ReviewTokenIssueResponse(token);
    }

    @Override
    public ReviewTokenIssuerPublicIdentity getPublicIdentity() {
        return publicIdentity;
    }

    @Override
    public Representation getRepresentation() {
        final ObjectRepresentation obj = AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
        obj.put("keyPair", keyPair.getRepresentation());
        return obj;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ReviewTokenIssuer that = (ReviewTokenIssuer) o;
        return Objects.equals(pp, that.pp) &&
                Objects.equals(keyPair, that.keyPair);
    }

    @Override
    public int hashCode() {
        return Objects.hash(pp, keyPair);
    }
}
