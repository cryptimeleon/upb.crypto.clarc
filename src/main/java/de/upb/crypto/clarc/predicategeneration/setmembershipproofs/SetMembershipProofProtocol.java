package de.upb.crypto.clarc.predicategeneration.setmembershipproofs;

import de.upb.crypto.clarc.predicategeneration.inequalityproofs.InequalityProofProtocol;
import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.expressions.arith.*;
import de.upb.crypto.clarc.protocols.expressions.comparison.ArithComparisonExpression;
import de.upb.crypto.clarc.protocols.expressions.comparison.GroupElementEqualityExpression;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrChallenge;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrResponse;
import de.upb.crypto.clarc.protocols.parameters.*;
import de.upb.crypto.clarc.protocols.protocolfactory.GeneralizedSchnorrProtocolFactory;
import de.upb.crypto.clarc.protocols.simulator.SpecialHonestVerifierSimulator;
import de.upb.crypto.craco.accumulators.nguyen.*;
import de.upb.crypto.craco.commitment.interfaces.CommitmentValue;
import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;


/**
 * A Protocol realizing the general construction for a setMembership proof.
 * Given the public parameters g_1, h, C \in G', the public parameter nguyenPP for a {@link NguyenAccumulator} and
 * \Omega, the set of ZP values where it is proven that \alpha is a member in<br>
 * <p>
 * The prover gets additionally r, \alpha as input.<br>
 * <p>
 * Firstly (in the announcement Step of this protocol), compute V := AccCreate(nguyenPP, \Omega)
 * Afterwards, the prover computes W_alpha:=WitCreate(pp,\Omega,i), where \alpha is equal to the i-th value of \Omega.
 * Next, the prover chooses z uniformly at random from Z_p * and computes W=W_\alpha ^z.
 * W is send along with the announcement, when Prover and Verifier run the following GeneralizedSchnorrProtocol:<br>
 * <p>
 * C = g2^r \op h^\alpha <br>
 * e(W,g1~^s)^-1 = e(W,g1~) ^\alpha  \op e(V,g1~ ^-1 )^z<br>
 * <br>
 * The witnesses are: r,\alpha, z <br>
 * The verifier accepts iff W =/= 1 and verify(a,c,r)=1
 */
public class SetMembershipProofProtocol extends SigmaProtocol {

    public static final String R = "r_";
    public static final String ALPHA = "alpha_";
    public static final String Z = "z_";

    @Represented
    private GeneralizedSchnorrProtocol innerProtocol;
    @Represented
    private Group groupOfW;
    @Represented(structure = "groupOfW", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement w;

    /**
     * Constructor for the prover.
     *
     * @param randomValueOfCommitment random value of commitment
     * @param alpha                   value of attribute in commitment / value stored in credential a specific position
     * @param publicParameters        fully specified {@link SetMembershipPublicParameters}
     * @param uniqueName              of the protocol
     */
    public SetMembershipProofProtocol(Zp.ZpElement randomValueOfCommitment, Zp.ZpElement alpha, PublicParameters
            publicParameters, String uniqueName) {
        super(new Witness[]{new EmptyWitness(uniqueName)}, publicParameters);
        if (Arrays.stream(problems).anyMatch(problem -> !(problem instanceof EmptyProblem))) {
            throw new IllegalArgumentException("The given Problems are not valid");
        }
        if (!(publicParameters instanceof SetMembershipPublicParameters)) {
            throw new IllegalArgumentException("The given public parameters are invalid");
        }

        SetMembershipPublicParameters setPP = (SetMembershipPublicParameters) publicParameters;

        // Compute V := AccCreate(nguyenPP, \Omega)
        NguyenAccumulator accumulator = new NguyenAccumulator(setPP.getNguyenAccumulatorPublicParameters());
        NguyenAccumulatorValue v = accumulator.create(setPP.getSetMembers());

        // W_alpha:=WitCreate(pp,\Omega,i), where \alpha is equal to the i-th value of \Omega
        NguyenWitness wAlpha =
                (NguyenWitness) accumulator.createWitness(setPP.getSetMembers(), new NguyenAccumulatorIdentity(alpha));

        // Choose z uniformly at random from Zp*
        Zp.ZpElement z = setPP.getZp().getUniformlyRandomUnit();
        this.w = wAlpha.getValue().pow(z);
        this.groupOfW = w.getStructure();

        // Store r, alpha and z in the witness
        this.witnesses = new Witness[]{new SetMembershipWitness(randomValueOfCommitment, alpha, z, uniqueName)};

        // generate inner protocol
        ArithComparisonExpression[] problemInnerProtocol = new ArithComparisonExpression[]{
                getFirstEquation(setPP, uniqueName),
                getSecondEquation(setPP, v, w, uniqueName)};
        GeneralizedSchnorrProtocolFactory factory =
                new GeneralizedSchnorrProtocolFactory(problemInnerProtocol, setPP.getZp());

        Map<String, Zp.ZpElement> wintessMap = new LinkedHashMap<>();
        wintessMap.put(R + uniqueName, randomValueOfCommitment);
        wintessMap.put(ALPHA + uniqueName, alpha);
        wintessMap.put(Z + uniqueName, z);
        this.innerProtocol = factory.createProverGeneralizedSchnorrProtocol(wintessMap);
    }

    /**
     * Constructor for the verifier
     * This constructor constructs an entity, that will be expanded in the verify-step using the announcement!
     *
     * @param publicParameters nearly specified {@link SetMembershipPublicParameters}, the {@link CommitmentValue}
     *                         should be missing since it is not known at this time
     * @param uniqueName       a unique name for the protocol
     */
    public SetMembershipProofProtocol(SetMembershipPublicParameters publicParameters, String uniqueName) {
        super(new Witness[]{new EmptyWitness(uniqueName)},
                publicParameters);
        SetMembershipPublicParameters setPP = (SetMembershipPublicParameters) this.publicParameters;


        /* Note: The value of W is currently set to the neutral element of G2. THis is an invalid value, thus the
         verification will fail if tried with this value for w. It cannot be set to the actual value of w, since
         the verifier will receive w in the verify-phase */
        this.w = setPP.getG2().getStructure().getNeutralElement();

        final GeneralizedSchnorrProtocolFactory factory;

        // In case no commitment is set (in case only the "recreation" protocol is being built)
        // We can not compute the actual problem equations
        if (setPP.getCommitment() == null) {
            factory = new GeneralizedSchnorrProtocolFactory(new ArithComparisonExpression[0], setPP.getZp());
        } else {

            // Compute V := AccCreate(nguyenPP, \Omega)
            NguyenAccumulator accumulator = new NguyenAccumulator(setPP.getNguyenAccumulatorPublicParameters());
            NguyenAccumulatorValue v = accumulator.create(setPP.getSetMembers());

            // Create problem equations for the GenSchnorrProtocol
            ArithComparisonExpression eq1 = getFirstEquation(setPP, uniqueName);
            ArithComparisonExpression eq2 = getSecondEquation(setPP, v, w, uniqueName);

            // Create a GenSchnorrProtocol
            factory = new GeneralizedSchnorrProtocolFactory(new ArithComparisonExpression[]{eq1, eq2}, setPP.getZp());
        }
        this.innerProtocol = factory.createVerifierGeneralizedSchnorrProtocol();
    }

    public SetMembershipProofProtocol(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    /**
     * Computes C = g2^r \op h^\alpha <br>
     *
     * @param setPP      of the setMembershipProof
     * @param uniqueName of the protocol
     * @return the problem equation
     */
    private ArithComparisonExpression getFirstEquation(SetMembershipPublicParameters setPP, String uniqueName) {
        // To ensure that all witnesses values are mapped correctly, the unique name is used as postfix
        ProductGroupElementExpression rhs = new ProductGroupElementExpression();
        rhs.addElement(new PowerGroupElementExpression(new NumberGroupElementLiteral(setPP.getG2()),
                new ZnVariable(R + uniqueName)));
        rhs.addElement(new PowerGroupElementExpression(new NumberGroupElementLiteral(setPP.getH()),
                new ZnVariable(ALPHA + uniqueName)));
        return new GroupElementEqualityExpression(new NumberGroupElementLiteral(setPP.getCommitment()), rhs);
    }

    /**
     * Computes   e(W,g1~^s)^-1 = e(W,g1~) ^\alpha  \op e(V,g1~ ^-1 )^z
     *
     * @param setPP of the setMembershipProof
     * @param v     accumulator value
     * @param w     :=WitCreate(pp,\Omega,i) ^z
     * @return the problem equation
     */
    private ArithComparisonExpression getSecondEquation(SetMembershipPublicParameters setPP, NguyenAccumulatorValue v,
                                                        GroupElement w, String uniqueName) {
        NguyenAccumulatorPublicParameters accPP = setPP.getNguyenAccumulatorPublicParameters();
        // Firstly, compute e(W,g1~^s)^-1
        GroupElement lhs = accPP.getBilinearMap().apply(w, accPP.getG_Tilde_Power_S()).inv();

        ProductGroupElementExpression rhs = new ProductGroupElementExpression();
        rhs.addElement(new PowerGroupElementExpression(
                new PairingGroupElementExpression(
                        accPP.getBilinearMap(),
                        new NumberGroupElementLiteral(w),
                        new NumberGroupElementLiteral(accPP.getG_Tilde())),
                new ZnVariable(ALPHA + uniqueName)));
        rhs.addElement(new PowerGroupElementExpression(
                new PairingGroupElementExpression(
                        accPP.getBilinearMap(),
                        new NumberGroupElementLiteral(v.getValue()),
                        new NumberGroupElementLiteral(accPP.getG_Tilde().inv())),
                new ZnVariable(Z + uniqueName)));

        return new GroupElementEqualityExpression(new NumberGroupElementLiteral(lhs), rhs);
    }

    @Override
    public SigmaProtocol setWitnesses(List<Witness> witnesses) {
        List<SetMembershipWitness> filteredList =
                witnesses.stream().filter(w -> w instanceof SetMembershipWitness)
                        .map(w -> (SetMembershipWitness) w).collect(Collectors.toList());
        if (filteredList.size() > 1) {
            throw new IllegalArgumentException("Too many witnesses given");
        }
        if (!filteredList.isEmpty()) {
            this.witnesses[0] = filteredList.get(0);
        }
        // Delegate to inner protocol
        this.innerProtocol = this.innerProtocol.setWitnesses(witnesses);
        return this;
    }

    @Override
    public Challenge createChallengeFromByteArray(byte[] integer) {
        BigInteger representedChallenge = new BigInteger(integer);
        return new GeneralizedSchnorrChallenge((((SetMembershipPublicParameters) getPublicParameters())
                .getZp().createZnElement(representedChallenge)));
    }

    @Override
    public boolean isFulfilled() {
        if (this.innerProtocol != null) {
            return innerProtocol.isFulfilled();
        }
        return false;
    }

    @Override
    public SetMembershipAnnouncement[] generateAnnouncements() {
        // Return combination of W and the received announcement
        return new SetMembershipAnnouncement[]{new SetMembershipAnnouncement(innerProtocol.generateAnnouncements(), w)};

    }

    @Override
    public Challenge chooseChallenge() {
        return new GeneralizedSchnorrChallenge(((SetMembershipPublicParameters) this.publicParameters)
                .getZp().getUniformlyRandomElement());
    }

    @Override
    public Response[] generateResponses(Challenge challenge) {
        return innerProtocol.generateResponses(challenge);
    }

    @Override
    public boolean verify(Announcement[] announcements, Challenge challenge, Response[] responses) {
        if (announcements.length != 1 || !(announcements[0] instanceof SetMembershipAnnouncement)) {
            throw new IllegalArgumentException("The given Announcement is incorrect");
        }
        if (!(challenge instanceof GeneralizedSchnorrChallenge)) {
            throw new IllegalArgumentException("The challenge is invalid");
        }
        if (Arrays.stream(responses).anyMatch(resp -> !(resp instanceof GeneralizedSchnorrResponse))) {
            throw new IllegalArgumentException("The given responses are invalid");
        }
        SetMembershipPublicParameters setPP = (SetMembershipPublicParameters) this.publicParameters;
        SetMembershipAnnouncement setMembershipAnnouncement = (SetMembershipAnnouncement) announcements[0];

        // Compute V := AccCreate(nguyenPP, \Omega)
        NguyenAccumulator accumulator = new NguyenAccumulator(setPP.getNguyenAccumulatorPublicParameters());
        NguyenAccumulatorValue v = accumulator.create(setPP.getSetMembers());

        ArithComparisonExpression[] problemInnerProtocol = new ArithComparisonExpression[]{
                getFirstEquation(setPP, this.witnesses[0].getName()),
                getSecondEquation(setPP, v, setMembershipAnnouncement.getW(), this.witnesses[0].getName())};

        GeneralizedSchnorrProtocolFactory factory = new GeneralizedSchnorrProtocolFactory(problemInnerProtocol, (
                (SetMembershipPublicParameters) this.publicParameters).getZp());
        this.innerProtocol = factory.createVerifierGeneralizedSchnorrProtocol();

        // As defined, it returns true if underlying protocol is ok and W <>1
        boolean wUneqalNeutralElement = !(setMembershipAnnouncement.getW().equals(
                ((SetMembershipPublicParameters) this.publicParameters).getG2().getStructure().getNeutralElement()));
        return wUneqalNeutralElement && innerProtocol.verify(setMembershipAnnouncement.getAnnouncements(), challenge,
                responses);
    }

    @Override
    public Announcement recreateAnnouncement(Representation representation) {
        if (this.innerProtocol == null) {
            throw new IllegalArgumentException("Cannot recreate announcement, no announcement created using this " +
                    "protocol. Please create a verifier Protocol");
        }
        return new SetMembershipAnnouncement(representation,
                ((SetMembershipPublicParameters) this.publicParameters).getG2().getStructure(), this.innerProtocol);
    }

    @Override
    public Challenge recreateChallenge(Representation representation) {
        return new GeneralizedSchnorrChallenge(representation,
                ((SetMembershipPublicParameters) this.publicParameters).getZp());
    }

    @Override
    public Response recreateResponse(Representation representation) {
        if (this.innerProtocol == null) {
            throw new IllegalArgumentException("Cannot recreate response, no announcement created using this " +
                    "protocol. Please create an verifier Protocol");
        }
        return innerProtocol.recreateResponse(representation);
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
        SetMembershipProofProtocol that = (SetMembershipProofProtocol) o;
        return Objects.equals(getInnerProtocol(), that.getInnerProtocol()) &&
                Objects.equals(groupOfW, that.groupOfW) &&
                Objects.equals(w, that.w);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), getInnerProtocol(), groupOfW, w);
    }

    @Override
    public SpecialHonestVerifierSimulator getSimulator() {
        return new SetMembershipProtocolSimulator(this);
    }

    public GeneralizedSchnorrProtocol getInnerProtocol() {
        return innerProtocol;
    }

    /**
     * Update the value of the parameter w in the inner protocol and in this protocol as well
     * Used on verifier side when the value of w is extracted form the announcement in the verify.
     * Additionally, this is used in the simulator to set the simulated w to the protocol.
     *
     * @param w new value of w
     * @return the updated {@link InequalityProofProtocol}
     */
    public SetMembershipProofProtocol updateW(GroupElement w) {
        this.w = w;
        // Recompute second equaiton
        SetMembershipPublicParameters setPP = (SetMembershipPublicParameters) this.publicParameters;
        // Compute V := AccCreate(nguyenPP, \Omega)
        NguyenAccumulator accumulator = new NguyenAccumulator(setPP.getNguyenAccumulatorPublicParameters());
        NguyenAccumulatorValue v = accumulator.create(setPP.getSetMembers());

        // Create problem equations for the GenSchnorrProtocol
        ArithComparisonExpression eq1 = getFirstEquation(setPP, witnesses[0].getName());
        ArithComparisonExpression eq2 = getSecondEquation(setPP, v, w, witnesses[0].getName());

        // Create a GenSchnorrProtocol
        GeneralizedSchnorrProtocolFactory factory = new GeneralizedSchnorrProtocolFactory(
                new ArithComparisonExpression[]{eq1, eq2}, setPP.getZp());
        this.innerProtocol = factory.createVerifierGeneralizedSchnorrProtocol();
        return this;
    }
}
