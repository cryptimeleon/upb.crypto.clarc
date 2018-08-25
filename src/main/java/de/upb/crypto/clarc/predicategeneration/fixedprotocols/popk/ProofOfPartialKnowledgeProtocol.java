package de.upb.crypto.clarc.predicategeneration.fixedprotocols.popk;

import de.upb.crypto.clarc.predicategeneration.policies.SigmaProtocolPolicyFact;
import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrChallenge;
import de.upb.crypto.clarc.protocols.parameters.*;
import de.upb.crypto.clarc.protocols.simulator.SpecialHonestVerifierSimulator;
import de.upb.crypto.clarc.protocols.simulator.Transcript;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.craco.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.craco.secretsharing.ThresholdTreeSecretSharing;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedMap;
import de.upb.crypto.math.serialization.annotations.RepresentedSet;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;

/**
 * This {@link SigmaProtocol} describes a proof of partial knowledge.
 * <p>
 * For a given {@link ThresholdPolicy} with {@link SigmaProtocolPolicyFact} as leaves a
 * {@link ThresholdTreeSecretSharing} instance is constructed and used to share the received {@link Challenge}.
 * <p>
 * For every protocol for which {@link SigmaProtocol#isFulfilled} == false the protocol's
 * {@link SpecialHonestVerifierSimulator} is used to generate a valid {@link Transcript} of the protocol execution.
 * <p>
 * For these simulated protocols {@link ThresholdTreeSecretSharing#completeShares} is used to reconstruct
 * the correct {@link Challenge} and compute the corresponding {@link ProofOfPartialKnowledgeResponse} for each
 * (simulated) protocol.
 * <p>
 * The verifier accepts iff {@link ThresholdTreeSecretSharing#checkShareConsistency} == true for the given partial
 * challenges (shares) and internal protocols accept their corresponding
 * ({@link Announcement}, {@link Challenge}, {@link Response})-tuple.
 */
public class ProofOfPartialKnowledgeProtocol extends SigmaProtocol {

    @Represented
    private Zp zp;
    @Represented
    private ThresholdPolicy policyWithProtocolLeaves;
    @RepresentedSet(elementRestorer = @Represented)
    private Set<SigmaProtocolPolicyFact> fulfilledProtocols;
    @RepresentedMap(keyRestorer = @Represented, valueRestorer = @Represented(structure = "zp", recoveryMethod = Zp
            .ZpElement.RECOVERY_METHOD))
    private Map<Integer, Zp.ZpElement> unqualifiedShares;
    @RepresentedMap(keyRestorer = @Represented, valueRestorer = @Represented)
    private Map<Integer, Transcript> simulatedProtocolExecutions;

    private ThresholdTreeSecretSharing secretSharing;
    private Map<Integer, SigmaProtocol> protocolMapping;


    //Verifier constructor
    public ProofOfPartialKnowledgeProtocol(ProofOfPartialKnowledgePublicParameters publicParameters,
                                           ThresholdPolicy transformedProtocolPolicy) {
        this(new EmptyWitness(), publicParameters, transformedProtocolPolicy);
    }

    //Prover constructor
    public ProofOfPartialKnowledgeProtocol(Witness witness, ProofOfPartialKnowledgePublicParameters publicParameters,
                                           ThresholdPolicy transformedProtocolPolicy) {
        super(new Witness[]{witness}, publicParameters);
        this.zp = publicParameters.getZp();
        this.policyWithProtocolLeaves = transformedProtocolPolicy;
        this.fulfilledProtocols = collectFulfilledLeaves(policyWithProtocolLeaves);
        setupSecretSharing();
    }

    public ProofOfPartialKnowledgeProtocol(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
        setupSecretSharing();
    }


    private void setupSecretSharing() {
        ThresholdPolicy dualPolicy = ThresholdPolicyInverter.invertThresholdPolicy(policyWithProtocolLeaves);
        secretSharing = new ThresholdTreeSecretSharing(dualPolicy, zp,
                ((ProofOfPartialKnowledgePublicParameters) publicParameters).getLsssProvider());
        protocolMapping = secretSharing.getShareReceiverMap().entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey,
                        entry -> ((SigmaProtocolPolicyFact) entry.getValue()).getProtocol()));
    }


    /**
     * Collect a set of all leaves of the policy tree, which are {@link SigmaProtocolPolicyFact}, that are fulfilled
     * with respect to the currently available {@link Witness}.
     *
     * @param policy {@link ThresholdPolicy} which leaves are {@link SigmaProtocolPolicyFact} to collect the leaves,
     *               whose inner {@link SigmaProtocol#isFulfilled} == true.
     * @return A set of all {@link SigmaProtocolPolicyFact} leaves of the given policy whose inner
     * {@link SigmaProtocol#isFulfilled} == true.
     */
    private Set<SigmaProtocolPolicyFact> collectFulfilledLeaves(ThresholdPolicy policy) {
        Set<SigmaProtocolPolicyFact> fulfilledLeaves = new HashSet<>();
        for (Policy childPolicy : policy.getChildren()) {
            if (childPolicy instanceof SigmaProtocolPolicyFact) {
                SigmaProtocolPolicyFact leaf = (SigmaProtocolPolicyFact) childPolicy;
                if (leaf.getProtocol().isFulfilled()) {
                    fulfilledLeaves.add(leaf);
                }
            } else if (childPolicy instanceof ThresholdPolicy) {
                fulfilledLeaves.addAll(collectFulfilledLeaves((ThresholdPolicy) childPolicy));
            } else {
                throw new IllegalArgumentException("Malformed Policy!");
            }
        }
        return fulfilledLeaves;
    }


    @Override
    public ProofOfPartialKnowledgeProtocol setWitnesses(List<Witness> witnesses) {
        //Since the names of the witnesses are unique among all protocols, we can simply delegate to the leaves
        setWitnessesForPolicyWithProtocolLeaves(policyWithProtocolLeaves, witnesses);
        return this;
    }

    /**
     * Traverses the given {@link Policy} and sets the witnesses for all {@link SigmaProtocol} found.
     *
     * @param policy    the {@link ThresholdPolicy} or {@link SigmaProtocolPolicyFact} to set the witnesses for
     * @param witnesses list of {@link Witness} to set for the inner protocols
     */
    private void setWitnessesForPolicyWithProtocolLeaves(Policy policy, List<Witness> witnesses) {
        if (policy instanceof SigmaProtocolPolicyFact) {
            ((SigmaProtocolPolicyFact) policy).getProtocol().setWitnesses(witnesses);
        } else if (policy instanceof ThresholdPolicy) {
            for (Policy child : ((ThresholdPolicy) policy).getChildren()) {
                setWitnessesForPolicyWithProtocolLeaves(child, witnesses);
            }
        } else {
            throw new IllegalArgumentException("The given policy is neither a ThresHoldPolicy nor a " +
                    "SigmaProtocolPolicyFact!");
        }
    }

    @Override
    public Challenge createChallengeFromByteArray(byte[] integer) {
        return new GeneralizedSchnorrChallenge(zp.createZnElement(new BigInteger(integer)));
    }

    @Override
    public boolean isFulfilled() {
        //Since the protocols in the leaves already know whether they are fulfilled
        //there is no need to pass any PolicyFacts
        return policyWithProtocolLeaves.isFulfilled(Collections.emptySet());
    }


    @Override
    public Announcement[] generateAnnouncements() {
        Set<Integer> unfulfilledShareIds = secretSharing.getShareReceiverMap().entrySet().parallelStream()
                .filter(entry ->
                        fulfilledProtocols.stream()
                                .noneMatch(prot ->
                                        prot.equals(
                                                entry.getValue())))
                .map(Map.Entry::getKey)
                .collect(Collectors.toSet());

        unqualifiedShares = secretSharing.getShares(zp.getOneElement()).entrySet().parallelStream()
                .filter(entry -> unfulfilledShareIds.contains(entry.getKey()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        simulatedProtocolExecutions = new HashMap<>(unqualifiedShares.size());

        Announcement[] announcements =
                new ProofOfPartialKnowledgeAnnouncement[secretSharing.getShareReceiverMap().size()];
        //Per contract of linear secret sharing all shares are indexed from 1,..,n.
        //Therefore we need to "shift" the position by 1
        for (int i = 1; i <= announcements.length; i++) {
            SigmaProtocol protocol = ((SigmaProtocolPolicyFact) secretSharing.getShareReceiver(i)).getProtocol();
            if (unqualifiedShares.containsKey(i)) {
                Challenge c = new GeneralizedSchnorrChallenge(unqualifiedShares.get(i));
                simulatedProtocolExecutions.put(i, protocol.getSimulator().simulate(c));
                announcements[i - 1] = new ProofOfPartialKnowledgeAnnouncement(i,
                        simulatedProtocolExecutions.get(i).getAnnouncements());
            } else {
                announcements[i - 1] = new ProofOfPartialKnowledgeAnnouncement(i, protocol.generateAnnouncements());
            }
        }
        return announcements;
    }

    @Override
    public Challenge chooseChallenge() {
        return new GeneralizedSchnorrChallenge(zp.getUniformlyRandomElement());
    }

    @Override
    public Response[] generateResponses(Challenge challenge) {
        if (!(challenge instanceof GeneralizedSchnorrChallenge)) {
            throw new IllegalArgumentException("Unsupported type of challenge! " + challenge);
        }
        GeneralizedSchnorrChallenge c = (GeneralizedSchnorrChallenge) challenge;
        Map<Integer, Zp.ZpElement> completeShares = secretSharing.completeShares(c.getChallenge(), unqualifiedShares);

        //Collect ids of the leaves which contain the fulfilled protocols.
        Set<Integer> fulfilledShareIds = secretSharing.getShareReceiverMap().entrySet().parallelStream()
                .filter(entry -> fulfilledProtocols.stream().anyMatch(prot ->
                        prot.equals(entry.getValue())))
                .map(Map.Entry::getKey)
                .collect(Collectors.toSet());

        Response[] responses = new ProofOfPartialKnowledgeResponse[completeShares.size()];
        //Per contract of the linear secret sharing all shares are indexed from 1,..,n.
        //Therefore we need to "shift" the position by 1
        for (int i = 1; i <= completeShares.size(); i++) {
            SigmaProtocol protocol = ((SigmaProtocolPolicyFact) secretSharing.getShareReceiver(i)).getProtocol();
            Zp.ZpElement ci = completeShares.get(i);
            if (fulfilledShareIds.contains(i)) {
                responses[i - 1] = new ProofOfPartialKnowledgeResponse(i,
                        protocol.generateResponses(new GeneralizedSchnorrChallenge(completeShares.get(i))), ci);
            } else {
                responses[i - 1] = new ProofOfPartialKnowledgeResponse(i,
                        simulatedProtocolExecutions.get(i).getResponses(), ci);
            }
        }

        return responses;
    }

    @Override
    public boolean verify(Announcement[] announcements, Challenge challenge, Response[] responses) {
        if (announcements == null ||
                Arrays.stream(announcements).anyMatch(a -> !(a instanceof ProofOfPartialKnowledgeAnnouncement))) {
            throw new IllegalArgumentException();
        }
        if (!(challenge instanceof GeneralizedSchnorrChallenge)) {
            throw new IllegalArgumentException();
        }
        if (responses == null ||
                Arrays.stream(responses).anyMatch(r -> !(r instanceof ProofOfPartialKnowledgeResponse))) {
            throw new IllegalArgumentException();
        }
        if (announcements.length != responses.length) {
            throw new IllegalArgumentException();
        }

        ProofOfPartialKnowledgeAnnouncement[] popkAnnouncements =
                Arrays.stream(announcements)
                        .map(a -> (ProofOfPartialKnowledgeAnnouncement) a)
                        .toArray(ProofOfPartialKnowledgeAnnouncement[]::new);
        GeneralizedSchnorrChallenge c = (GeneralizedSchnorrChallenge) challenge;
        ProofOfPartialKnowledgeResponse[] popkResponses = Arrays.stream(responses)
                .map(r -> (ProofOfPartialKnowledgeResponse) r)
                .toArray(ProofOfPartialKnowledgeResponse[]::new);

        //collect challenges and check share consistency
        Map<Integer, Zp.ZpElement> challenges = new HashMap<>(popkResponses.length);
        for (int i = 1; i <= popkResponses.length; i++) {
            ProofOfPartialKnowledgeResponse response = popkResponses[i - 1];
            challenges.put(i, response.getChallenge());
        }

        if (!secretSharing.checkShareConsistency(c.getChallenge(), challenges)) {
            return false;
        }

        //Per contract of linear secret sharing all shares (and therefore the challenges) are indexed from 1,..,n.
        //Therefore we need to "shift" the position by 1
        //check that for all i: p_i.verify(a_i, c_i, r_i) == true
        for (int i = 1; i <= popkResponses.length; i++) {
            SigmaProtocol protocol = protocolMapping.get(i);
            Announcement[] protAnnouncements = popkAnnouncements[i - 1].getAnnouncements();
            Challenge protChallenge = new GeneralizedSchnorrChallenge(challenges.get(i));
            Response[] protResponses = popkResponses[i - 1].getResponses();
            if (!protocol.verify(protAnnouncements, protChallenge, protResponses)) {
                return false;
            }
        }
        //The verifier accepts iff all partial challenges are consistent to the challenge sent earlier
        // and all protocols in the leaves of the tree are successfully verified
        return true;
    }

    @Override
    public Announcement recreateAnnouncement(Representation representation) {
        int protocolId = representation.obj().get("protocolId").bigInt().getInt();
        return new ProofOfPartialKnowledgeAnnouncement(representation, protocolMapping.get(protocolId));
    }

    @Override
    public Challenge recreateChallenge(Representation representation) {
        return new GeneralizedSchnorrChallenge(representation, zp);
    }

    @Override
    public Response recreateResponse(Representation representation) {
        int protocolId = representation.obj().get("protocolId").bigInt().getInt();
        return new ProofOfPartialKnowledgeResponse(representation, protocolMapping.get(protocolId));
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }


    @Override
    public SpecialHonestVerifierSimulator getSimulator() {
        return new ProofOfPartialKnowledgeSimulator(this);
    }

    public ThresholdPolicy getPolicyWithProtocolLeaves() {
        return policyWithProtocolLeaves;
    }

    public ThresholdTreeSecretSharing getSecretSharing() {
        return secretSharing;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ProofOfPartialKnowledgeProtocol that = (ProofOfPartialKnowledgeProtocol) o;
        return Objects.equals(zp, that.zp) &&
                Objects.equals(policyWithProtocolLeaves, that.policyWithProtocolLeaves);
    }

    @Override
    public int hashCode() {
        return Objects.hash(zp, policyWithProtocolLeaves);
    }
}
