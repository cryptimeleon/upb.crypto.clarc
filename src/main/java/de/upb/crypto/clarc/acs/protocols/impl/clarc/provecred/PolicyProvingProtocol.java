package de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred;

import de.upb.crypto.clarc.acs.subpolicyproving.SubPolicyProvingProtocol;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.popk.ProofOfPartialKnowledgeProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.clarc.protocols.parameters.Witness;
import de.upb.crypto.clarc.protocols.simulator.SpecialHonestVerifierSimulator;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedList;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * This specific {@link SigmaProtocolWithDisclosure} encapsulates a {@link ProofOfPartialKnowledgeProtocol} which proves
 * the fulfillment of a {@link Policy}. Therefore the {@link ProofOfPartialKnowledgeProtocol} executes a
 * {@link SubPolicyProvingProtocol} for each sub policies contained in the {@link Policy} to prove.
 */
public class PolicyProvingProtocol extends SigmaProtocolWithDisclosure {

    @Represented
    private ProofOfPartialKnowledgeProtocol proofOfPartialKnowledgeProtocol;
    @RepresentedList(elementRestorer = @Represented)
    private List<DisclosedAttributes> disclosedAttributes;

    PolicyProvingProtocol(ProofOfPartialKnowledgeProtocol proofOfPartialKnowledgeProtocol,
                          List<DisclosedAttributes> disclosedAttributes) {
        this.proofOfPartialKnowledgeProtocol = proofOfPartialKnowledgeProtocol;
        this.disclosedAttributes = disclosedAttributes;
    }

    PolicyProvingProtocol(ProofOfPartialKnowledgeProtocol proofOfPartialKnowledgeProtocol) {
        this(proofOfPartialKnowledgeProtocol, new ArrayList<>());
    }

    public PolicyProvingProtocol(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    @Override
    public List<DisclosedAttributes> getDisclosedAttributes() {
        return new ArrayList<>(disclosedAttributes);
    }

    @Override
    public SpecialHonestVerifierSimulator getSimulator() {
        return proofOfPartialKnowledgeProtocol.getSimulator();
    }

    @Override
    public ProofOfPartialKnowledgeProtocol setWitnesses(List<Witness> witnesses) {
        throw new UnsupportedOperationException("Currently setting witnesses manually is not supported. " +
                "A unique naming scheme for witnesses needs to be implemented first.");
    }

    @Override
    public boolean isFulfilled() {
        return proofOfPartialKnowledgeProtocol.isFulfilled();
    }


    @Override
    public Announcement[] generateAnnouncements() {
        Announcement[] announcements = proofOfPartialKnowledgeProtocol.generateAnnouncements();
        return new Announcement[]{new PolicyProvingAnnouncement(announcements, disclosedAttributes)};
    }

    @Override
    public Challenge chooseChallenge() {
        return proofOfPartialKnowledgeProtocol.chooseChallenge();
    }

    @Override
    public Response[] generateResponses(Challenge challenge) {
        return proofOfPartialKnowledgeProtocol.generateResponses(challenge);
    }

    @Override
    public boolean verify(Announcement[] announcements, Challenge challenge, Response[] responses) {
        if (announcements == null || announcements.length != 1 ||
                !(announcements[0] instanceof PolicyProvingAnnouncement)) {
            throw new IllegalArgumentException();
        }
        PolicyProvingAnnouncement announcement = (PolicyProvingAnnouncement) announcements[0];

        // The verifier should not be able to extract the disclosed values if the verification fails
        if (proofOfPartialKnowledgeProtocol.verify(announcement.getPopkAnnouncements(), challenge, responses)) {
            // After successful verification the disclosed attributes can be extracted via `getDisclosedAttributes()`
            this.disclosedAttributes = announcement.getDisclosedAttributes();
            return true;
        }
        return false;
    }

    @Override
    public Announcement recreateAnnouncement(Representation representation) {
        return new PolicyProvingAnnouncement(representation, proofOfPartialKnowledgeProtocol);
    }

    @Override
    public Challenge recreateChallenge(Representation representation) {
        return proofOfPartialKnowledgeProtocol.recreateChallenge(representation);
    }

    @Override
    public Challenge createChallengeFromByteArray(byte[] integer) {
        return proofOfPartialKnowledgeProtocol.createChallengeFromByteArray(integer);
    }

    @Override
    public Response recreateResponse(Representation representation) {
        return proofOfPartialKnowledgeProtocol.recreateResponse(representation);
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
        PolicyProvingProtocol that = (PolicyProvingProtocol) o;
        return Objects.equals(proofOfPartialKnowledgeProtocol, that.proofOfPartialKnowledgeProtocol) &&
                Objects.equals(disclosedAttributes, that.disclosedAttributes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), proofOfPartialKnowledgeProtocol, disclosedAttributes);
    }
}
