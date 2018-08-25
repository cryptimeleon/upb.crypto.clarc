package de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials;

import de.upb.crypto.clarc.acs.attributes.AttributeDefinition;
import de.upb.crypto.clarc.acs.issuer.Issuer;
import de.upb.crypto.clarc.acs.issuer.credentials.Attributes;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.IssueIssuableProtocolFactory;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Pseudonym;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.user.NonInteractiveIssuableRequest;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.clarc.acs.user.impl.clarc.credentials.NonInteractiveCredentialRequest;
import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.FiatShamirHeuristic;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.craco.commitment.interfaces.CommitmentValue;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.math.hash.impl.SHA256HashFunction;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.List;
import java.util.Objects;

public class CredentialIssuer implements Issuer<Attributes, PSCredential> {
    @Represented
    private PublicParameters pp;
    private final IssuerKeyPair issuerKeyPair;
    @Represented
    private CredentialIssuerPublicIdentity publicIdentity;

    public CredentialIssuer(PublicParameters pp, IssuerKeyPair issuerKeyPair,
                            List<AttributeDefinition> attributeSpace) {
        this.pp = pp;
        this.issuerKeyPair = issuerKeyPair;
        this.publicIdentity =
                new CredentialIssuerPublicIdentity(issuerKeyPair.getVerificationKey()
                        .getRepresentation(), attributeSpace);
    }

    public CredentialIssuer(PublicParameters pp,
                            List<AttributeDefinition> attributeSpace) {
        this.pp = pp;
        final IssuerKeyPairFactory issuerFactory = new IssuerKeyPairFactory();
        issuerKeyPair = issuerFactory.create(pp, attributeSpace.size());
        this.publicIdentity =
                new CredentialIssuerPublicIdentity(issuerKeyPair.getVerificationKey()
                        .getRepresentation(), attributeSpace);
    }

    /**
     * Deserializes an issuer instance
     *
     * @param representation The serializes {@link CredentialIssuer} instance
     */
    public CredentialIssuer(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
        final ObjectRepresentation obj = representation.obj();
        issuerKeyPair = new IssuerKeyPair(obj.get("issuerKeyPair"),
                pp.getZp(),
                pp.getBilinearMap().getG1(),
                pp.getBilinearMap().getG2()
        );
    }

    @Override
    public InteractiveIssueCredentialProcess initInteractiveIssueProcess(CommitmentValue commitment,
                                                                         de.upb.crypto.clarc.acs.pseudonym.Pseudonym pseudonym,
                                                                         Attributes issuable,
                                                                         Announcement[] announcements) {
        if (!(pseudonym instanceof Pseudonym)) {
            throw new IllegalArgumentException("Unsupported Pseudonym type!");
        }
        if (!(commitment instanceof PedersenCommitmentValue)) {
            throw new IllegalArgumentException("Unsupported Commitment type!");
        }
        return new InteractiveIssueCredentialProcess(pp, issuerKeyPair, (Pseudonym) pseudonym,
                (PedersenCommitmentValue) commitment, announcements, issuable, publicIdentity);
    }

    @Override
    public CredentialIssueResponse issueNonInteractively(
            NonInteractiveIssuableRequest nonInteractiveIssuableRequest) {
        final NonInteractiveCredentialRequest clarcCredentialRequest =
                (NonInteractiveCredentialRequest) nonInteractiveIssuableRequest;
        IssueIssuableProtocolFactory protocolFactory = new IssueIssuableProtocolFactory(
                pp, issuerKeyPair.getVerificationKey(),
                clarcCredentialRequest.getPseudonym(),
                clarcCredentialRequest.getCommitment()
        );
        final InteractiveThreeWayAoK protocol = protocolFactory.getProtocol();
        FiatShamirHeuristic fiatShamirHeuristic = new FiatShamirHeuristic(protocol, new SHA256HashFunction());
        if (!fiatShamirHeuristic.verify(clarcCredentialRequest.getProof())) {
            return null;
        }
        PSCredential blindedCredential = CreateCredentialHelper.createBlindedCredential(pp,
                clarcCredentialRequest.getIssuable(), issuerKeyPair, publicIdentity,
                clarcCredentialRequest.getCommitment());
        return new CredentialIssueResponse(blindedCredential);
    }

    @Override
    public CredentialIssuerPublicIdentity getPublicIdentity() {
        return publicIdentity;
    }

    @Override
    public Representation getRepresentation() {
        final ObjectRepresentation representation = AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
        representation.put("issuerKeyPair", issuerKeyPair.getRepresentation());
        return representation;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CredentialIssuer issuer = (CredentialIssuer) o;
        return Objects.equals(pp, issuer.pp) &&
                Objects.equals(issuerKeyPair, issuer.issuerKeyPair) &&
                Objects.equals(publicIdentity, issuer.publicIdentity);
    }

    @Override
    public int hashCode() {
        return Objects.hash(pp, issuerKeyPair, publicIdentity);
    }
}
