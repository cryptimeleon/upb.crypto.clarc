package de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred;

import de.upb.crypto.clarc.acs.verifier.credentials.RepresentableSignature;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.popk.ProofOfPartialKnowledgeProtocol;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrChallenge;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.clarc.protocols.parameters.Witness;
import de.upb.crypto.clarc.protocols.simulator.SpecialHonestVerifierSimulator;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * This specific {@link SigmaProtocolWithDisclosure} is used to prove the fulfillment of a given {@link Policy} as well
 * as possession of a valid master-credential. Therefore it encapsulates a {@link PolicyProvingProtocol} and a
 * {@link GeneralizedSchnorrProtocol} which both need to accept for this protocol to accept.
 */
public class PolicyProvingWithMasterCredProtocol extends SigmaProtocolWithDisclosure {
    @Represented
    private PolicyProvingProtocol policyProvingProtocol;
    @Represented
    private GeneralizedSchnorrProtocol masterCredProvingProtocol;
    @Represented
    private Zp zp;
    @Represented
    private RepresentableSignature masterCred;

    PolicyProvingWithMasterCredProtocol(Zp zp,
                                        PolicyProvingProtocol policyProvingProtocol,
                                        GeneralizedSchnorrProtocol masterCredProvingProtocol,
                                        RepresentableSignature masterCred) {
        this.zp = zp;
        this.policyProvingProtocol = policyProvingProtocol;
        this.masterCredProvingProtocol = masterCredProvingProtocol;
        this.masterCred = masterCred;
    }

    public PolicyProvingWithMasterCredProtocol(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);

    }

    @Override
    public List<DisclosedAttributes> getDisclosedAttributes() {
        return policyProvingProtocol.getDisclosedAttributes();
    }

    @Override
    public SpecialHonestVerifierSimulator getSimulator() {
        throw new UnsupportedOperationException("The highest level of the protocols can not be simulated!");
    }

    @Override
    public ProofOfPartialKnowledgeProtocol setWitnesses(List<Witness> witnesses) {
        throw new UnsupportedOperationException("Currently setting witnesses manually is not supported. " +
                "A unique naming scheme for witnesses needs to be implemented first.");
    }

    @Override
    public boolean isFulfilled() {
        return policyProvingProtocol.isFulfilled() && masterCredProvingProtocol.isFulfilled();
    }


    @Override
    public Announcement[] generateAnnouncements() {
        Announcement[] policyProofAnnouncements = policyProvingProtocol.generateAnnouncements();
        Announcement[] masterCredAnnouncements = masterCredProvingProtocol.generateAnnouncements();
        return new Announcement[]{new PolicyProvingWithMasterCredAnnouncement(policyProofAnnouncements,
                masterCredAnnouncements, masterCred)};
    }

    @Override
    public Challenge chooseChallenge() {
        return new GeneralizedSchnorrChallenge(zp.getUniformlyRandomElement());
    }

    @Override
    public Response[] generateResponses(Challenge challenge) {
        Response[] policyProofResponses = policyProvingProtocol.generateResponses(challenge);
        Response[] masterCredResponses = masterCredProvingProtocol.generateResponses(challenge);
        return new Response[]{new PolicyProvingWithMasterCredResponse(policyProofResponses, masterCredResponses)};
    }

    @Override
    public boolean verify(Announcement[] announcements, Challenge challenge, Response[] responses) {
        if (announcements == null || announcements.length != 1 ||
                !(announcements[0] instanceof PolicyProvingWithMasterCredAnnouncement)) {
            throw new IllegalArgumentException();
        }
        if (responses == null || responses.length != 1 ||
                !(responses[0] instanceof PolicyProvingWithMasterCredResponse)) {
            throw new IllegalArgumentException();
        }
        PolicyProvingWithMasterCredAnnouncement announcement =
                (PolicyProvingWithMasterCredAnnouncement) announcements[0];
        Announcement[] policyProofAnnouncements = announcement.getPolicyAnnouncements();
        Announcement[] masterCredAnnouncements = announcement.getMasterCredAnnouncements();

        PolicyProvingWithMasterCredResponse response = (PolicyProvingWithMasterCredResponse) responses[0];
        Response[] policyProofResponses = response.getPolicyResponses();
        Response[] masterCredResponses = response.getMasterCredResponses();

        boolean verifiedMasterCred =
                masterCredProvingProtocol.verify(masterCredAnnouncements, challenge, masterCredResponses);
        boolean verifiedPolicyProof =
                policyProvingProtocol.verify(policyProofAnnouncements, challenge, policyProofResponses);

        return verifiedMasterCred && verifiedPolicyProof;
    }

    @Override
    public Announcement recreateAnnouncement(Representation representation) {
        return new PolicyProvingWithMasterCredAnnouncement(representation, policyProvingProtocol,
                masterCredProvingProtocol);
    }

    @Override
    public Challenge recreateChallenge(Representation representation) {
        return new GeneralizedSchnorrChallenge(representation, zp);
    }

    @Override
    public Challenge createChallengeFromByteArray(byte[] integer) {
        return new GeneralizedSchnorrChallenge(zp.createZnElement(new BigInteger(integer)));
    }

    @Override
    public Response recreateResponse(Representation representation) {
        return new PolicyProvingWithMasterCredResponse(representation, policyProvingProtocol,
                masterCredProvingProtocol);
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
        PolicyProvingWithMasterCredProtocol that = (PolicyProvingWithMasterCredProtocol) o;
        return Objects.equals(policyProvingProtocol, that.policyProvingProtocol) &&
                Objects.equals(masterCredProvingProtocol, that.masterCredProvingProtocol) &&
                Objects.equals(zp, that.zp);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), policyProvingProtocol, masterCredProvingProtocol, zp);
    }
}
