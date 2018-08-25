package de.upb.crypto.clarc.acs.protocols.proveNym;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.expressions.arith.*;
import de.upb.crypto.clarc.protocols.expressions.comparison.ArithComparisonExpression;
import de.upb.crypto.clarc.protocols.expressions.comparison.GroupElementEqualityExpression;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.clarc.protocols.parameters.Witness;
import de.upb.crypto.clarc.protocols.protocolfactory.GeneralizedSchnorrProtocolFactory;
import de.upb.crypto.clarc.protocols.simulator.SpecialHonestVerifierSimulator;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.*;

/**
 * A wrapper protocol for the prove nym protocol, that's a {@link GeneralizedSchnorrProtocol}
 * It proves the equation. <br>
 * nym = g^r \op h^usk
 */
public class ProveNymProtocol extends SigmaProtocol {

    public static final String USK = "usk";
    public static final String NYM_RANDOM = "nymRandom";
    @Represented
    private GeneralizedSchnorrProtocol protocol;

    public ProveNymProtocol(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    /**
     * A constructed for the prover
     *
     * @param nymRandom                 the random value used to randomize the usk
     * @param usk                       of the user
     * @param singleMessageCommitmentPP used to create the nym
     * @param pseudonym                 of the user used in this proof
     */
    public ProveNymProtocol(Zp.ZpElement nymRandom, Zp.ZpElement usk,
                            PedersenPublicParameters singleMessageCommitmentPP, PedersenCommitmentValue pseudonym) {
        super();
        GeneralizedSchnorrProtocolFactory factory = new GeneralizedSchnorrProtocolFactory(
                getProblemEquation(singleMessageCommitmentPP, pseudonym),
                new Zp(singleMessageCommitmentPP.getP()));

        Map<String, Zp.ZpElement> witnessMap = new HashMap<>();
        witnessMap.put(USK, usk);
        witnessMap.put(NYM_RANDOM, nymRandom);
        protocol = factory.createProverGeneralizedSchnorrProtocol(witnessMap);
        this.problems = protocol.getProblems();
        this.witnesses = protocol.getWitnesses();
        this.publicParameters = protocol.getPublicParameters();
    }

    /**
     * A constructed for the prover
     *
     * @param singleMessageCommitmentPP used to create the nym
     * @param pseudonym                 of the user used in this proof
     */
    public ProveNymProtocol(PedersenPublicParameters singleMessageCommitmentPP, PedersenCommitmentValue pseudonym) {
        super();
        GeneralizedSchnorrProtocolFactory factory = new GeneralizedSchnorrProtocolFactory(
                getProblemEquation(singleMessageCommitmentPP, pseudonym),
                new Zp(singleMessageCommitmentPP.getP()));

        protocol = factory.createVerifierGeneralizedSchnorrProtocol();
        this.problems = protocol.getProblems();
        this.witnesses = protocol.getWitnesses();
        this.publicParameters = protocol.getPublicParameters();
    }


    private static ArithComparisonExpression[] getProblemEquation(PedersenPublicParameters singleMessageCommitmentPP,
                                                                  PedersenCommitmentValue commitment) {
        List<ArithGroupElementExpression> factors = new ArrayList<>();
        factors.add(new PowerGroupElementExpression(new NumberGroupElementLiteral(singleMessageCommitmentPP.getG()),
                new ZnVariable(NYM_RANDOM)));
        factors.add(new PowerGroupElementExpression(new NumberGroupElementLiteral(singleMessageCommitmentPP.getH()[0]),
                new ZnVariable(USK)));

        ProductGroupElementExpression rhs = new ProductGroupElementExpression(factors);
        GroupElementEqualityExpression eq = new GroupElementEqualityExpression(
                new NumberGroupElementLiteral(commitment.getCommitmentElement()), rhs);
        return new ArithComparisonExpression[]{eq};
    }

    @Override
    public SpecialHonestVerifierSimulator getSimulator() {
        return protocol.getSimulator();
    }

    @Override
    public SigmaProtocol setWitnesses(List<Witness> witnesses) {
        protocol.setWitnesses(witnesses);
        return this;
    }

    @Override
    public boolean isFulfilled() {
        return protocol.isFulfilled();
    }

    @Override
    public Announcement[] generateAnnouncements() {
        return protocol.generateAnnouncements();
    }

    @Override
    public Challenge chooseChallenge() {
        return protocol.chooseChallenge();
    }

    @Override
    public Response[] generateResponses(Challenge challenge) {
        return protocol.generateResponses(challenge);
    }

    @Override
    public boolean verify(Announcement[] announcements, Challenge challenge, Response[] responses) {
        return protocol.verify(announcements, challenge, responses);
    }

    @Override
    public Announcement recreateAnnouncement(Representation representation) {
        return protocol.recreateAnnouncement(representation);
    }

    @Override
    public Challenge recreateChallenge(Representation representation) {
        return protocol.recreateChallenge(representation);
    }

    @Override
    public Challenge createChallengeFromByteArray(byte[] integer) {
        return protocol.createChallengeFromByteArray(integer);
    }

    @Override
    public Response recreateResponse(Representation representation) {
        return protocol.recreateResponse(representation);
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        ProveNymProtocol that = (ProveNymProtocol) o;
        return Objects.equals(protocol, that.protocol);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), protocol);
    }
}
