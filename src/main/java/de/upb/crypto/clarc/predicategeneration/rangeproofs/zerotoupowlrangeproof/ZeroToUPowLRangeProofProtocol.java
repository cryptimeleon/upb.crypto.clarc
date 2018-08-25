package de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.expressions.arith.*;
import de.upb.crypto.clarc.protocols.expressions.comparison.ArithComparisonExpression;
import de.upb.crypto.clarc.protocols.expressions.comparison.GroupElementEqualityExpression;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrChallenge;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.clarc.protocols.parameters.Witness;
import de.upb.crypto.clarc.protocols.protocolfactory.GeneralizedSchnorrProtocolFactory;
import de.upb.crypto.clarc.protocols.simulator.SpecialHonestVerifierSimulator;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulator;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorIdentity;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorPublicParameters;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorValue;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.*;

/**
 * A Protocol realizing the general construction for a range proof.
 * It is proven hat the value of alpha (committed to in the commitment) is in the interval <b>[0,2^l)</b>.
 * <p>
 * Given are the public parameters g_1, h, C \in G', the public parameter nguyenPP for a {@link NguyenAccumulator} and
 * \Omega = {0,..., u-1}<br>
 * <p>
 * The prover gets additionally r, \alpha as input.<br>
 * <p>
 * <p>
 * Both  compute V := AccCreate(nguyenPP, \Omega).
 * Next, the prover computes a representation of \alpha as follows:<br>
 * \alpha = \sum_{j=0}^{l-1} (\alpha_j * u^j).
 * Then W_j = WitCreate(pp,\Omega,a_j) is computed, z_j chosen uniformly at random from Zp* and computes W_j^ = W_j
 * ^z_j.<br>
 * <p>
 * W_j^ are send along with the announcement, when Prover and Verifier run  the following GeneralizedSchnorrProtocol:
 * <br>
 * <p>
 * C = g2^r \op \prod_{j=0}^{l-1} (h^ (u^j)) ^ \alpha_j <br>
 * e(W,g1~^s)^-1 = e(W,g1~) ^\alpha_j  \op e(V,g1~ ^-1 )^z_j (for j =0,...,l-1)<br>
 * <br>
 * The witnesses are: r,\alpha_j, z_j (for j = 0,...,l-1) <br>
 * The verifier accepts iff W =/= 1 and verify(a,c,r)=1
 */
public class ZeroToUPowLRangeProofProtocol extends SigmaProtocol {

    public static final String PREFIX_COMMITMENT_RANDOM = "r_";
    public static final String PREFIX_ALPHA = "alpha_";
    public static final String PREFIX_ADDITIONAL_RANDOM = "z_";

    @Represented
    private String uniqueName;

    @Represented
    private GeneralizedSchnorrProtocol innerProtocol;

    private GroupElement[] w_jHats;

    /**
     * The blinding value used for each w_jHat
     */
    private Zp.ZpElement[] z_j;

    @Represented
    private NguyenAccumulator accumulator;

    /**
     * Cached value for isFulfilled(). null if not yet determined
     */
    private Boolean isFulfilled;

    public ZeroToUPowLRangeProofProtocol(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    /**
     * Constructor for the prover.
     *
     * @param publicParameters fully specified {@link ZeroToUPowLRangeProofPublicParameters}
     * @param uniqueName       of the protocol
     * @param witness          the witness for this protocol or null
     */
    public ZeroToUPowLRangeProofProtocol(ZeroToUPowLRangeProofPublicParameters publicParameters,
                                         String uniqueName, RangeProofWitness witness) {
        super(new Witness[]{witness}, publicParameters);
        accumulator = new NguyenAccumulator(publicParameters.getNguyenAccumulatorPublicParameters());
        if (isNotValidParameterCombination(publicParameters))
            throw new IllegalArgumentException("Invalid public parameters");
        this.uniqueName = uniqueName;
    }


    private boolean isNotValidParameterCombination(ZeroToUPowLRangeProofPublicParameters rangePP) {
        // Check that u^l - 1  < p
        BigInteger uPowLSub1 = rangePP.getBase().pow(rangePP.getExponent()).subtract(BigInteger.ONE);
        if (uPowLSub1.compareTo(rangePP.getZp().size()) >= 0) {
            return true;
        }
        // Check that u <= q
        return rangePP.getBase().compareTo(
                rangePP.getNguyenAccumulatorPublicParameters().getUpperBoundForAccumulatableIdentities()) >= 0;
    }

    @Override
    public ZeroToUPowLRangeProofAnnouncement[] generateAnnouncements() {
        ZeroToUPowLRangeProofPublicParameters rangePP = getPublicParameters();
        Zp zp = rangePP.getZp();
        NguyenAccumulator accumulator = new NguyenAccumulator(rangePP.getNguyenAccumulatorPublicParameters());

        //Generate values alpha_j (the u-ary representation of the witness alpha)
        Zp.ZpElement[] alpha_j = getUaryRepresentationOf(getWitness().getAlpha().getInteger());

        //Create corresponding blinded accumulator witnesses W_jhat = W_j^z_j for each digit alpha_j
        w_jHats = new GroupElement[alpha_j.length];
        z_j = new Zp.ZpElement[alpha_j.length];
        for (int j = 0; j < w_jHats.length; j++) {
            z_j[j] = zp.getUniformlyRandomUnit();
            w_jHats[j] = getPublicParameters().getAccumulatorWitness(new NguyenAccumulatorIdentity(alpha_j[j])).getValue().pow(z_j[j]);
        }

        // generate inner protocol.
        this.innerProtocol = createInternalProverProtocol(w_jHats, z_j, alpha_j);

        //Return combination of W_jHats for the inner protocol and the received announcement
        return new ZeroToUPowLRangeProofAnnouncement[]{
                new ZeroToUPowLRangeProofAnnouncement(innerProtocol.generateAnnouncements(), w_jHats)};
    }

    @Override
    public Challenge chooseChallenge() {
        return new GeneralizedSchnorrChallenge(((ZeroToUPowLRangeProofPublicParameters) this.publicParameters)
                .getZp().getUniformlyRandomElement());
    }

    @Override
    public Response[] generateResponses(Challenge challenge) {
        return new Response[]{new ZeroToUPowLRangeProofResponse(innerProtocol.generateResponses(challenge))};
    }

    @Override
    public boolean verify(Announcement[] announcements, Challenge challenge, Response[] responses) {
        if (announcements.length != 1 || !(announcements[0] instanceof ZeroToUPowLRangeProofAnnouncement)) {
            throw new IllegalArgumentException("The given Announcement is incorrect");
        }
        if (!(challenge instanceof GeneralizedSchnorrChallenge)) {
            throw new IllegalArgumentException("The challenge is invalid");
        }
        if (responses.length != 1 || !(responses[0] instanceof ZeroToUPowLRangeProofResponse)) {
            throw new IllegalArgumentException("The given response is invalid");
        }

        ZeroToUPowLRangeProofAnnouncement rangeProofAnnouncement = (ZeroToUPowLRangeProofAnnouncement) announcements[0];
        ZeroToUPowLRangeProofResponse response = (ZeroToUPowLRangeProofResponse) responses[0];

        //Create inner protocol
        GeneralizedSchnorrProtocol schnorrProtocol = createInternalVerifierProtocol(rangeProofAnnouncement.getRandomizedAccWitnesses());

        //Check that none of the W_jHats are the neutral element
        if (Arrays.stream(rangeProofAnnouncement.getRandomizedAccWitnesses())
                .anyMatch(GroupElement::isNeutralElement)) {
            return false;
        }

        //Check that the Schnorr protocol accepts
        return schnorrProtocol.verify(rangeProofAnnouncement.getAnnouncementsOfInnerProtocol(),
                challenge,
                response.innerProtocolResponses);
    }

    protected GeneralizedSchnorrProtocol createInternalVerifierProtocol(GroupElement[] w_jHats) {
        // Compute the problem equation for the innerProtocol and create it using the GenSchnorrFactory
        ArithComparisonExpression[] problemLowerBoundProtocol = computeProblemEquations(getPublicParameters().getCommitment(), w_jHats, getPublicParameters().getAccumulatorValue(),
                uniqueName, getPublicParameters());
        GeneralizedSchnorrProtocolFactory factoryInner = new GeneralizedSchnorrProtocolFactory(
                problemLowerBoundProtocol, getPublicParameters().getZp());
        return factoryInner.createVerifierGeneralizedSchnorrProtocol();
    }

    /**
     * Creates the inner Schnorr protocol for the range proof (Camenisch, Chaabouni, and Shelat [CCs08])
     * The unique name is prefixed.
     */
    protected GeneralizedSchnorrProtocol createInternalProverProtocol(GroupElement[] w_jHats, Zp.ZpElement[] z_j, Zp.ZpElement[] alpha_js) {
        ArithComparisonExpression[] problem = computeProblemEquations(getPublicParameters().getCommitment(), w_jHats,
                getPublicParameters().getAccumulatorValue(), uniqueName, getPublicParameters());
        GeneralizedSchnorrProtocolFactory factory = new GeneralizedSchnorrProtocolFactory(problem,
                getPublicParameters().getZp());
        return factory.createProverGeneralizedSchnorrProtocol(getWitnessMapping(getWitness().getOpenValue(), alpha_js,
                z_j, uniqueName));
    }

    @Override
    public Announcement recreateAnnouncement(Representation representation) {
        return new ZeroToUPowLRangeProofAnnouncement(representation,
                getPublicParameters().getG2().getStructure(),
                this::createInternalVerifierProtocol);
    }

    @Override
    public Challenge recreateChallenge(Representation representation) {
        return new GeneralizedSchnorrChallenge(representation, ((ZeroToUPowLRangeProofPublicParameters) this
                .publicParameters).getZp());
    }

    @Override
    public Response recreateResponse(Representation representation) {
        return new ZeroToUPowLRangeProofResponse(representation, getPublicParameters().getZp());
    }

    protected Zp.ZpElement[] getUaryRepresentationOf(BigInteger alpha) {
        Zp zp = getPublicParameters().getZp();
        int exponent = getPublicParameters().getExponent();
        BigInteger base = getPublicParameters().getBase();
        Zp.ZpElement[] alpha_js = new Zp.ZpElement[exponent];
        BigInteger remainderAlpha = alpha;

        if (alpha.compareTo(base.pow(exponent)) >= 0)
            throw new IllegalArgumentException(alpha.toString() + " is larger than the allowed " + base.pow(exponent) + " for the range proof (invalid witness)");

        for (int j = exponent - 1; j >= 0; j--) {
            if (base.pow(j).compareTo(remainderAlpha) <= 0) {
                BigInteger[] div = remainderAlpha.divideAndRemainder(base.pow(j));
                // Set a_J = remainderAlpha /  (u ^j)
                alpha_js[j] = zp.getElement(div[0]);
                //  Set remainderAlpha =  remainderAlpha %  (u ^j)
                remainderAlpha = div[1];
            } else {
                alpha_js[j] = zp.getZeroElement();
            }
        }

        return alpha_js;
    }

    private Map<String, Zp.ZpElement> getWitnessMapping(Zp.ZpElement randomValueOfCommitment, Zp.ZpElement[] alpha_js,
                                                        Zp.ZpElement[] z_js, String uniqueName) {
        Map<String, Zp.ZpElement> witnessMap = new HashMap<>();
        witnessMap.put(PREFIX_COMMITMENT_RANDOM + uniqueName, randomValueOfCommitment);
        for (int j = 0; j < alpha_js.length; j++) {
            witnessMap.put(PREFIX_ALPHA + j + "_" + uniqueName, alpha_js[j]);
            witnessMap.put(PREFIX_ADDITIONAL_RANDOM + j + "_" + uniqueName, z_js[j]);
        }
        return witnessMap;
    }

    /**
     * Computes the problem equations :  C = g2^r \op \prod_{j=0}^{l-1} (h^(u^j)) ^ \alpha_j <br>
     * e(W,g1~^s)^-1 = e(W,g1~) ^\alpha_j  \op e(V,g1~ ^-1 )^z_j (for j =0,...,l-1)<br>
     *
     * @param c       the commitment value
     * @param w_jHats values of W_jHat
     * @param v       the accumulatorValue V = ACCCreate(pp, \Omega)
     * @param rangePP pps of proof
     * @return the problem equations
     */
    private ArithComparisonExpression[] computeProblemEquations(GroupElement c, GroupElement[] w_jHats,
                                                                NguyenAccumulatorValue v,
                                                                String uniqueName,
                                                                ZeroToUPowLRangeProofPublicParameters rangePP) {
        // number of w_jHats +1 since there is one additional equation
        ArithComparisonExpression[] problems = new ArithComparisonExpression[w_jHats.length + 1];
        problems[0] = getFirstEquation(rangePP, c, uniqueName);
        for (int j = 0; j < w_jHats.length; j++) {
            problems[j + 1] = getSecondEquation(rangePP, v, w_jHats[j], j + "_", uniqueName);
        }
        return problems;
    }

    /**
     * Computes C = g2^r \op \prod_{j=0}^{l-1} (h^(u^j)) ^ \alpha_j
     *
     * @param rangePP    of the setMembershipProof
     * @param uniqueName of the protocol
     * @return the problem equation
     */
    private ArithComparisonExpression getFirstEquation(ZeroToUPowLRangeProofPublicParameters rangePP,
                                                       GroupElement commitment,
                                                       String uniqueName) {
        // To ensure that all witnesses values are mapped correctly, the unique name is used as postfix
        ProductGroupElementExpression rhs = new ProductGroupElementExpression();
        rhs.addElement(new PowerGroupElementExpression(new NumberGroupElementLiteral(rangePP.getG2()),
                new ZnVariable(PREFIX_COMMITMENT_RANDOM + uniqueName)));
        // To stay consistent with the other problem equations, the unique name is prefixed with "j_" (j=0,..,l-1)
        for (int j = 0; j < rangePP.getExponent(); j++) {
            BigInteger uPowj = rangePP.getBase().pow(j);
            rhs.addElement(new PowerGroupElementExpression(
                    new PowerGroupElementExpression(new NumberGroupElementLiteral(rangePP.getH()), new NumberZnElementLiteral(getPublicParameters().getZp().createZnElement(uPowj))),
                    new ZnVariable(PREFIX_ALPHA + j + "_" + uniqueName)));
        }
        return new GroupElementEqualityExpression(new NumberGroupElementLiteral(commitment), rhs);
    }

    /**
     * Computes   e(W,g1~^s)^-1 = e(W,g1~) ^\alpha_j  \op e(V,g1~ ^-1 )^z_j
     *
     * @param setPP      of the setMembershipProof
     * @param v          accumulator value
     * @param wHad       :=WitCreate(pp,\Omega,i) ^z
     * @param prefixForJ used for \alpha and z
     * @param uniqueName of the protocol
     * @return the problem equation
     */
    private ArithComparisonExpression getSecondEquation(ZeroToUPowLRangeProofPublicParameters setPP,
                                                        NguyenAccumulatorValue v,
                                                        GroupElement wHad, String prefixForJ, String uniqueName) {
        NguyenAccumulatorPublicParameters accPP = setPP.getNguyenAccumulatorPublicParameters();
        // Firstly, compute e(W,g1~^s)^-1
        PairingGroupElementExpression lhs = new PairingGroupElementExpression(accPP.getBilinearMap(),
                new NumberGroupElementLiteral(wHad), new NumberGroupElementLiteral(accPP.getG_Tilde_Power_S()), BigInteger.ONE.negate());

        ProductGroupElementExpression rhs = new ProductGroupElementExpression();
        rhs.addElement(new PowerGroupElementExpression(
                new PairingGroupElementExpression(
                        accPP.getBilinearMap(),
                        new NumberGroupElementLiteral(wHad),
                        new NumberGroupElementLiteral(accPP.getG_Tilde())),
                new ZnVariable(PREFIX_ALPHA + prefixForJ + uniqueName)));
        rhs.addElement(new PowerGroupElementExpression(
                new PairingGroupElementExpression(
                        accPP.getBilinearMap(),
                        new NumberGroupElementLiteral(v.getValue().inv()),
                        new NumberGroupElementLiteral(accPP.getG_Tilde())),
                new ZnVariable(PREFIX_ADDITIONAL_RANDOM + prefixForJ + uniqueName)));
        return new GroupElementEqualityExpression(lhs, rhs);
    }

    @Override
    public ZeroToUPowLRangeProofProtocol setWitnesses(List<Witness> witnesses) {
        throw new UnsupportedOperationException("Not implemented");
        /*List<RangeProofWitness> filteredList =
                witnesses.stream().filter(w -> w instanceof RangeProofWitness)
                         .filter(w -> w.getName().equals(this.witnesses[0].getName()))
                         .map(w -> (RangeProofWitness) w).collect(Collectors.toList());
        if (filteredList.size() > 1) {
            throw new IllegalArgumentException("Too many witnesses given");
        }
        if (!filteredList.isEmpty()) {
            this.witnesses[0] = filteredList.get(0);
        }
        // Delegate to inner protocol
        this.innerProtocol = this.innerProtocol.setWitnesses(witnesses);
        return this;*/
    }

    @Override
    public Challenge createChallengeFromByteArray(byte[] integer) {
        BigInteger representedChallenge = new BigInteger(integer);
        return new GeneralizedSchnorrChallenge(getPublicParameters().getZp().createZnElement(representedChallenge));
    }

    @Override
    public boolean isFulfilled() {
        if (isFulfilled != null)
            return isFulfilled;
        if (getWitness() == null)
            return isFulfilled = false;
        BigInteger alpha = getWitness().getAlpha().getInteger();
        if (alpha.compareTo(getPublicParameters().getBase().pow(getPublicParameters().getExponent())) >= 0)
            return isFulfilled = false;
        if (alpha.signum() < 0)
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
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        ZeroToUPowLRangeProofProtocol that = (ZeroToUPowLRangeProofProtocol) o;
        return Objects.equals(uniqueName, that.uniqueName) &&
                Objects.equals(innerProtocol, that.innerProtocol) &&
                Objects.equals(accumulator, that.accumulator);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(super.hashCode(), uniqueName, innerProtocol, accumulator);
        return result;
    }

    @Override
    public SpecialHonestVerifierSimulator getSimulator() {
        return new ZeroToUPowLRangeProofProtocolSimulator(this);
    }

    public GeneralizedSchnorrProtocol getInnerProtocol() {
        return innerProtocol;
    }

    @Override
    public ZeroToUPowLRangeProofPublicParameters getPublicParameters() {
        return (ZeroToUPowLRangeProofPublicParameters) super.getPublicParameters();
    }

    public RangeProofWitness getWitness() {
        return (RangeProofWitness) getWitnesses()[0];
    }
}
