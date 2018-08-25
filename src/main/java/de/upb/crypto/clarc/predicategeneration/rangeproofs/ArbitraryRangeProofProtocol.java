package de.upb.crypto.clarc.predicategeneration.rangeproofs;

import de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof.RangeProofWitness;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof.ZeroToUPowLRangeProofProtocol;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof.ZeroToUPowLRangeProofPublicParameters;
import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrChallenge;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.clarc.protocols.parameters.Witness;
import de.upb.crypto.clarc.protocols.simulator.SpecialHonestVerifierSimulator;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulator;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.zn.Zn;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;


/**
 * PREFIX_LOWER_BOUND_PROTOCOL Protocol realizing the general construction for a range proof.
 * It is proven hat the value of alpa (committed to in the commitment) is in the interval [A,B].
 * Therefore, first of all values u and l are computed, s.t. 0 &lt; B - A &lt; min( p + 1 / 2u - 1 , u^l - 1 )
 * by unicode
 * Given are the public parameters g_1, h, C \in G', the public parameter nguyenPP for a {@link NguyenAccumulator} and
 * \Omega = {0,..., u-1}<br>
 * <p>
 * The prover gets additionally r, \alpha as input.<br>
 * <p>
 * Firstly C_A = C op h^(−A) (as commitment on  \alpha −A  with  random value r) and
 * C_B = C op h ^(− B + u^l − 1 ) (as commitment on \aloha − B + u^l − 1  with random value r) <br>
 * <p>
 * Afterwards, both  compute V := AccCreate(nguyenPP, \Omega).
 * Next, the prover computes a representation of \alpha as follows:<br>
 * \alpha = \sum_{j=0}^{l-1} (\alpha_j * u^j).
 * Then W_j = WitCreate(pp,\Omega,a_j) is computed, z_j chosen uniformly at random from Zp* and computes W_j^ = W_j
 * ^z_j.<br>
 * <p>
 * W_j^ are send along with the announcement, when Prover and Verifier run two instances of the following
 * GeneralizedSchnorrProtocol in parallel, once with C_A and one with C_B :<br>
 * <p>
 * C_x = g2^r_x \op \prod_{j=0}^{l-1} (h^ (u^j)) ^ \alpha_j ( x = A,B)<br>
 * e(W,g1~^s)^-1 = e(W,g1~) ^\alpha_j  \op e(V,g1~ ^-1 )^z_j (for j =0,...,l-1)<br>
 * <br>
 * The witnesses are: r,\alpha_j, z_j (for j = 0,...,l-1) <br>
 * The verifier accepts iff W =/= 1 and verify(a,c,r)=1
 */
public class ArbitraryRangeProofProtocol extends SigmaProtocol {
    public static final String PREFIX_LOWER_BOUND_PROTOCOL = "A_";
    public static final String PREFIX_UPPER_BOUND_PROTOCOL = "B_";

    @Represented
    private ZeroToUPowLRangeProofProtocol lowerBoundInnerProtocol, upperBoundInnerProtocol;

    @Represented
    protected String uniqueName;

    /**
     * Cached value for isFulfilled(). null if not yet determined
     */
    private Boolean isFulfilled;


    public ArbitraryRangeProofProtocol(ArbitraryRangeProofPublicParameters publicParameters, RangeProofWitness witness,
                                       String uniqueName) {
        super(new Witness[]{witness}, publicParameters);
        this.uniqueName = uniqueName;
    }

    public ArbitraryRangeProofProtocol(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    @Override
    public SigmaProtocol setWitnesses(List<Witness> witnesses) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public Challenge createChallengeFromByteArray(byte[] integer) {
        BigInteger representedChallenge = new BigInteger(integer);
        return new GeneralizedSchnorrChallenge((((ArbitraryRangeProofPublicParameters) getPublicParameters())
                .getZp().createZnElement(representedChallenge)));
    }

    @Override
    public boolean isFulfilled() {
        if (isFulfilled != null)
            return isFulfilled;
        if (getWitness() == null)
            return isFulfilled = false;
        BigInteger alpha = getWitness().getAlpha().getInteger();
        if (alpha.compareTo(getPublicParameters().getUpperBound()) > 0)
            return isFulfilled = false;
        if (getPublicParameters().getLowerBound().compareTo(alpha) > 0)
            return isFulfilled = false;

        //Check commitment
        GroupElement openingResult = getPublicParameters().getG2().asPowProductExpression().pow(getWitness().getOpenValue())
                .op(getPublicParameters().getH().asPowProductExpression().pow(getWitness().getAlpha()))
                .evaluate();
        if (!getPublicParameters().getCommitment().equals(openingResult))
            return isFulfilled = false;
        return isFulfilled = true;
    }

    @Override
    public ArbitraryRangeProofAnnouncement[] generateAnnouncements() {
        //Instantiate protocols
        lowerBoundInnerProtocol = instantiateInnerLowerBoundProtocol();
        upperBoundInnerProtocol = instantiateInnerUpperBoundProtocol();

        //Announcement is the announcements of the two inner protocols
        return new ArbitraryRangeProofAnnouncement[]{new ArbitraryRangeProofAnnouncement(
                lowerBoundInnerProtocol.generateAnnouncements(),
                upperBoundInnerProtocol.generateAnnouncements())};
    }

    /**
     * If a witness is known, instantiates a prover inner protocol, otherwise instantiates a verifier inner protocol
     */
    protected ZeroToUPowLRangeProofProtocol instantiateInnerLowerBoundProtocol() {
        RangeProofWitness witness = null;
        if (getWitness() != null) {
            witness = new RangeProofWitness(PREFIX_LOWER_BOUND_PROTOCOL + uniqueName,
                    getWitness().getAlpha().add(getPublicParameters().getZp().getElement(getPublicParameters().getLowerBound()).neg()),
                    getWitness().getOpenValue());
        }
        return instantiateInnerProtocol(computeC_A(), PREFIX_LOWER_BOUND_PROTOCOL, witness);
    }

    /**
     * If a witness is known, instantiates a prover inner protocol, otherwise instantiates a verifier inner protocol
     */
    protected ZeroToUPowLRangeProofProtocol instantiateInnerUpperBoundProtocol() {
        RangeProofWitness witness = null;
        if (getWitness() != null) {
            Zp zp = getPublicParameters().getZp();
            witness = new RangeProofWitness(PREFIX_UPPER_BOUND_PROTOCOL + uniqueName,
                    getWitness().getAlpha().add(zp.getElement(getPublicParameters().getUpperBound()).neg()) //alpha - B
                            .add(zp.getElement(getPublicParameters().getBase().pow(getPublicParameters().getExponent()))) // + u^l
                            .add(zp.getOneElement().neg()), // -1
                    getWitness().getOpenValue());
        }
        return instantiateInnerProtocol(computeC_B(), PREFIX_UPPER_BOUND_PROTOCOL, witness);
    }

    private ZeroToUPowLRangeProofProtocol instantiateInnerProtocol(GroupElement commitment, String prefix, RangeProofWitness witness) {
        ZeroToUPowLRangeProofPublicParameters ppLowerBound = new ZeroToUPowLRangeProofPublicParameters(getPublicParameters(), commitment);
        return new ZeroToUPowLRangeProofProtocol(ppLowerBound,
                prefix + uniqueName, witness);
    }

    @Override
    public Challenge chooseChallenge() {
        return new GeneralizedSchnorrChallenge(((ArbitraryRangeProofPublicParameters) this.publicParameters)
                .getZp().getUniformlyRandomElement());
    }

    @Override
    public Response[] generateResponses(Challenge challenge) {
        // Execute a Proof of partial Knowledge for an "And-Composition" here so use same challenge in both protocols
        return new Response[]{new ArbitraryRangeProofResponse(lowerBoundInnerProtocol.generateResponses(challenge),
                upperBoundInnerProtocol.generateResponses(challenge))};
    }

    @Override
    public boolean verify(Announcement[] announcements, Challenge challenge, Response[] responses) {
        if (announcements.length != 1 || !(announcements[0] instanceof ArbitraryRangeProofAnnouncement)) {
            throw new IllegalArgumentException("The given Announcement is incorrect");
        }
        if (!(challenge instanceof GeneralizedSchnorrChallenge)) {
            throw new IllegalArgumentException("The challenge is invalid");
        }
        if (responses.length != 1 || !(responses[0] instanceof ArbitraryRangeProofResponse)) {
            throw new IllegalArgumentException("The given response is invalid");
        }

        ArbitraryRangeProofAnnouncement arbitraryRangeProofAnnouncement =
                (ArbitraryRangeProofAnnouncement) announcements[0];
        ArbitraryRangeProofResponse response = (ArbitraryRangeProofResponse) responses[0];

        //Accept if both inner protools accept
        ZeroToUPowLRangeProofProtocol lowerBoundInnerProtocol = instantiateInnerLowerBoundProtocol();
        ZeroToUPowLRangeProofProtocol upperBoundInnerProtocol = instantiateInnerUpperBoundProtocol();

        return lowerBoundInnerProtocol.verify(arbitraryRangeProofAnnouncement.getAnnouncementsOfLowerBoundProtocol(),
                challenge, response.lowerBoundResponses)
                && upperBoundInnerProtocol.verify(arbitraryRangeProofAnnouncement.getAnnouncementsOfUpperBoundProtocol(),
                challenge, response.upperBoundResponses);
    }

    @Override
    public Announcement recreateAnnouncement(Representation representation) {
        ZeroToUPowLRangeProofProtocol lowerBoundInnerProtocol = instantiateInnerLowerBoundProtocol();
        ZeroToUPowLRangeProofProtocol upperBoundInnerProtocol = instantiateInnerUpperBoundProtocol();
        return new ArbitraryRangeProofAnnouncement(representation, getPublicParameters().getG2().getStructure(),
                upperBoundInnerProtocol, lowerBoundInnerProtocol);
    }

    @Override
    public Challenge recreateChallenge(Representation representation) {
        return new GeneralizedSchnorrChallenge(representation,
                ((ArbitraryRangeProofPublicParameters) this.publicParameters).getZp());
    }

    @Override
    public Response recreateResponse(Representation representation) {
        ZeroToUPowLRangeProofProtocol lowerBoundInnerProtocol = instantiateInnerLowerBoundProtocol();
        ZeroToUPowLRangeProofProtocol upperBoundInnerProtocol = instantiateInnerUpperBoundProtocol();
        return new ArbitraryRangeProofResponse(representation, lowerBoundInnerProtocol, upperBoundInnerProtocol);
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
        ArbitraryRangeProofProtocol that = (ArbitraryRangeProofProtocol) o;
        return Objects.equals(lowerBoundInnerProtocol, that.lowerBoundInnerProtocol) &&
                Objects.equals(upperBoundInnerProtocol, that.upperBoundInnerProtocol) &&
                Objects.equals(uniqueName, that.uniqueName);
    }

    @Override
    public int hashCode() {

        return Objects.hash(super.hashCode(), lowerBoundInnerProtocol, upperBoundInnerProtocol, uniqueName);
    }

    @Override
    public SpecialHonestVerifierSimulator getSimulator() {
        return new ArbitraryRangeProofProtocolSimulator(this);
    }

    protected GroupElement computeC_A() {
        Zp zp = getPublicParameters().getZp();
        return getPublicParameters().getCommitment()
                .op(getPublicParameters().getH().pow(zp.getElement(getPublicParameters().getLowerBound()).neg()));
    }

    protected GroupElement computeC_B() {
        Zp zp = getPublicParameters().getZp();
        return getPublicParameters().getCommitment()
                .op(getPublicParameters().getH().pow((Zn.ZnElement)
                        zp.getElement(getPublicParameters().getUpperBound()).neg()
                                .add(zp.getElement(getPublicParameters().getBase().pow(getPublicParameters().getExponent())))
                                .sub(zp.getElement(1))));
    }

    @Override
    public ArbitraryRangeProofPublicParameters getPublicParameters() {
        return (ArbitraryRangeProofPublicParameters) super.getPublicParameters();
    }

    public RangeProofWitness getWitness() {
        return (RangeProofWitness) getWitnesses()[0];
    }

}
