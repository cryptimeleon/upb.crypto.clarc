package de.upb.crypto.clarc.predicategeneration.inequalityproofs;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.expressions.arith.*;
import de.upb.crypto.clarc.protocols.expressions.comparison.ArithComparisonExpression;
import de.upb.crypto.clarc.protocols.expressions.comparison.GroupElementEqualityExpression;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrChallenge;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProblem;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrResponse;
import de.upb.crypto.clarc.protocols.parameters.*;
import de.upb.crypto.clarc.protocols.protocolfactory.GeneralizedSchnorrProtocolFactory;
import de.upb.crypto.clarc.protocols.simulator.SpecialHonestVerifierSimulator;
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
 * A Protocol realizing the general construction for an inequality proof.
 * It given the public parameters g_1, h, C \in G_1 and g_2,y \in G_2.
 * The prover gets additionally r, \alpha as input.
 * <p>
 * Firstly (in the announcement Step of this protocol), compute W=(g_2^\alpha \op y-1 )^z for z from Z until W \neq 1
 * Afterwards, run a generalized Schnorr protocol for the equations:<br>
 * <br>
 * 1=g_1^x_1 \op h^x_2 (C^-1)^x_3 <br>
 * W= (y^-1) ^x_3 \op g_2 ^x2<br>
 * <br>
 * The witnesses are:
 * x_1 = rz, x_2 =\alpha z , x_3=z
 */
public class InequalityProofProtocol extends SigmaProtocol {

    @Represented(structure = "zp", recoveryMethod = Zp.ZpElement.RECOVERY_METHOD)
    private Zp.ZpElement r, alpha;
    @Represented
    private Zp zp;
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
     * @param publicParameters        fully specified {@link InequalityPublicParameters}
     * @param uniqueName              of the protocol
     */
    public InequalityProofProtocol(Zp.ZpElement randomValueOfCommitment, Zp.ZpElement alpha, PublicParameters
            publicParameters, String uniqueName) {
        super(new Witness[]{new EmptyWitness(uniqueName)}, publicParameters);
        if (Arrays.stream(problems).anyMatch(problem -> !(problem instanceof EmptyProblem))) {
            throw new IllegalArgumentException("The given Problems are not valid");
        }
        this.r = randomValueOfCommitment;
        this.alpha = alpha;
        this.zp = randomValueOfCommitment.getStructure();

        this.w = generateW((InequalityPublicParameters) publicParameters);
        this.groupOfW = w.getStructure();
    }

    /**
     * Constructor for the verifier
     * This constructor constructs an entity, that will be expanded in the verify-step using the announcement!
     *
     * @param publicParameters nearly specified {@link InequalityPublicParameters}, the {@link CommitmentValue}
     *                         should be missing since it is not known at this time
     * @param uniqueName       a unique name for the protocol
     */
    public InequalityProofProtocol(InequalityPublicParameters publicParameters, String uniqueName) {
        super(new Witness[]{new EmptyWitness(uniqueName)},
                publicParameters);
        InequalityPublicParameters ipp = (InequalityPublicParameters) this.publicParameters;

        //Note: The value of W is currently set to the neutral element of G2. THis is an invalid value, thus the
        // verification will fail if tried with this value for w. It cannot be set to the actual value of w, since
        // the verifier will receive w in the verify-phase
        this.w = ipp.getG2().getStructure().getNeutralElement();
        this.groupOfW = ipp.getG2().getStructure();
        //Create problem equations for the GenSchnorrProtocol
        GroupElementEqualityExpression eq1 = getFirstEquation(ipp);

        GroupElementEqualityExpression eq2 = getSecondEquation(ipp, w);

        //Create a GenSchnorrProtocol
        GeneralizedSchnorrProtocolFactory factory = new GeneralizedSchnorrProtocolFactory(
                new ArithComparisonExpression[]{eq1, eq2}, ipp.getZp());
        this.innerProtocol = factory.createVerifierGeneralizedSchnorrProtocol();
    }

    public InequalityProofProtocol(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    private static Problem[] generateProblems(InequalityPublicParameters publicParameters, InequalityAnnouncement
            announcement) {
        return new Problem[]{
                new GeneralizedSchnorrProblem(getFirstEquation(publicParameters)),
                new GeneralizedSchnorrProblem(getSecondEquation(publicParameters, announcement.getW()))};
    }


    @Override
    public SigmaProtocol setWitnesses(List<Witness> witnesses) {
        List<InequalityWitness> filteredList = witnesses.stream().filter(w -> w instanceof InequalityWitness).map(w
                -> (InequalityWitness) w).collect(Collectors.toList());
        if (filteredList.size() > 1) {
            throw new IllegalArgumentException("Too many witnesses given");
        }
        if (!filteredList.isEmpty()) {
            this.witnesses[0] = filteredList.get(0);
        }
        //Delegate to inner protocol
        this.innerProtocol = this.innerProtocol.setWitnesses(witnesses);
        return this;
    }

    @Override
    public Challenge createChallengeFromByteArray(byte[] integer) {
        BigInteger representedChallenge = new BigInteger(integer);
        return new GeneralizedSchnorrChallenge((((InequalityPublicParameters) getPublicParameters())
                .getZp().createZnElement(representedChallenge)));
    }

    /**
     * checks if the sigma protocol is fulfilled using the witnesses stored inside the protocol
     *
     * @return true, if the witnesses fulfill the problem equations, false otherwise
     */
    @Override
    public boolean isFulfilled() {
        if (this.innerProtocol != null) {
            return innerProtocol.isFulfilled();
        } else return false;
    }

    /**
     * This is an algorithm for the creation of an announcement that chooses the randomness used internally. The
     * randomness
     * is stored internally nd will be used in the response.
     * Important: It is strictly recommended to use the generateResponse-Algorithm without randomness as input
     * parameter!
     *
     * @return an announcement for the protocol
     */
    @Override
    public InequalityAnnouncement[] generateAnnouncements() {
        //Return combination of W and the received announcement
        return new InequalityAnnouncement[]{new InequalityAnnouncement(innerProtocol.generateAnnouncements(), w)};

    }

    private GroupElement generateW(InequalityPublicParameters ipp) {
        Zp.ZpElement z;
        GroupElement w;
        do {
            //Compute W=   g_2^\alpha \op y-1 )^z until W  <> 1
            z = ipp.getZp().getUniformlyRandomUnit();
            w = ipp.getG2().pow(alpha).op(ipp.getY().inv()).pow(z);
        } while (w == ipp.getG2().getStructure().getNeutralElement());


        //Set witnesses with x_1 = rz, x_2 =\alpha z , x_3=z;
        this.witnesses = new Witness[]{new InequalityWitness(r.mul(z), alpha.mul(z), z, this.witnesses[0].getName())};

        //Create problem equations for the GenSchnorrProtocol
        GroupElementEqualityExpression eq1 = getFirstEquation(ipp);
        GroupElementEqualityExpression eq2 = getSecondEquation(ipp, w);

        //Create a GenSchnorrProtocol
        GeneralizedSchnorrProtocolFactory factory = new GeneralizedSchnorrProtocolFactory(
                new ArithComparisonExpression[]{eq1, eq2}, ipp.getZp());

        //Create Witness Map
        Map<String, Zp.ZpElement> witnessMapping = new HashMap<>();
        InequalityWitness witness = (InequalityWitness) this.getWitnesses()[0];
        witnessMapping.put("x_1", witness.getX1());
        witnessMapping.put("x_2", witness.getX2());
        witnessMapping.put("x_3", witness.getX3());
        this.innerProtocol = factory.createProverGeneralizedSchnorrProtocol(witnessMapping);
        return w;
    }


    /**
     * @param ipp f the protocols
     * @return an equation  1=g_1^x_1 \op h^x_2 (C^-1)^x_3
     */
    private static GroupElementEqualityExpression getFirstEquation(InequalityPublicParameters ipp) {
        //Create the first equation, that is  1=g_1^x_1 \op h^x_2  \op(C^-1)^x_3
        NumberGroupElementLiteral lhs = new NumberGroupElementLiteral(ipp.getG1().getStructure().getNeutralElement());
        ProductGroupElementExpression rhs = new ProductGroupElementExpression();
        rhs.addElement(new PowerGroupElementExpression(new NumberGroupElementLiteral(ipp.getG1()), new
                ZnVariable("x_1")));
        rhs.addElement(new PowerGroupElementExpression(new NumberGroupElementLiteral(ipp.getH()), new
                ZnVariable("x_2")));
        rhs.addElement(new PowerGroupElementExpression(new NumberGroupElementLiteral(ipp.getCommitment().inv()), new
                ZnVariable("x_3")));
        return new GroupElementEqualityExpression(lhs, rhs);

    }


    /**
     * Creates an {@link GroupElementEqualityExpression} for the expression  W= (y^-1) ^x_3 \op g_2 ^x2
     *
     * @param ipp pp of this protocol
     * @param w   value of previous computed w
     * @return the equation
     */
    private static GroupElementEqualityExpression getSecondEquation(InequalityPublicParameters ipp, GroupElement w) {
        //W= (y^-1) ^x_3 \op g_2 ^x2
        NumberGroupElementLiteral lhs = new NumberGroupElementLiteral(w);
        ProductGroupElementExpression rhs = new ProductGroupElementExpression();
        rhs.addElement(new PowerGroupElementExpression(new NumberGroupElementLiteral(ipp.getY().inv()), new
                ZnVariable("x_3")));
        rhs.addElement(new PowerGroupElementExpression(new NumberGroupElementLiteral(ipp.getG2()), new
                ZnVariable("x_2")));
        return new GroupElementEqualityExpression(lhs, rhs);

    }

    @Override
    public Challenge chooseChallenge() {
        return new GeneralizedSchnorrChallenge(((InequalityPublicParameters) this.publicParameters)
                .getZp().getUniformlyRandomElement());
    }

    @Override
    public Response[] generateResponses(Challenge challenge) {
        return innerProtocol.generateResponses(challenge);
    }


    @Override
    public boolean verify(Announcement[] announcements, Challenge challenge, Response[] responses) {
        if (announcements.length != 1 || !(announcements[0] instanceof InequalityAnnouncement)) {
            throw new IllegalArgumentException("The given Announcement is incorrect");
        }
        if (!(challenge instanceof GeneralizedSchnorrChallenge)) {
            throw new IllegalArgumentException("The challenge is invalid");
        }
        if (Arrays.stream(responses).anyMatch(resp -> !(resp instanceof GeneralizedSchnorrResponse))) {
            throw new IllegalArgumentException("The given responses are invalid");
        }

        InequalityAnnouncement inequalityAnnouncement = (InequalityAnnouncement) announcements[0];
        updateW(inequalityAnnouncement.getW());

        //As defined, it returns true if underlying protocol is ok and W <>1
        boolean wUneqalNeutralElement = !(inequalityAnnouncement.getW().equals(((InequalityPublicParameters) this
                .publicParameters).getG2().getStructure().getNeutralElement()));
        return wUneqalNeutralElement && innerProtocol.verify(inequalityAnnouncement.getAnnouncements(), challenge,
                responses);

    }


    @Override
    public Announcement recreateAnnouncement(Representation representation) {
        if (this.innerProtocol == null) {
            throw new IllegalArgumentException("Cannot recreate announcement, no announcement created using this " +
                    "protocol. Please create a verifier Protocol");
        }
        return new InequalityAnnouncement(representation,
                ((InequalityPublicParameters) this.publicParameters).getG2().getStructure(), this.innerProtocol);
    }


    @Override
    public Challenge recreateChallenge(Representation representation) {
        return new GeneralizedSchnorrChallenge(representation,
                ((InequalityPublicParameters) this.publicParameters).getZp());
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
        InequalityProofProtocol that = (InequalityProofProtocol) o;
        return Objects.equals(r, that.r) &&
                Objects.equals(alpha, that.alpha) &&
                Objects.equals(zp, that.zp) &&
                Objects.equals(innerProtocol, that.innerProtocol);
    }

    @Override
    public int hashCode() {
        return Objects.hash(r, alpha, zp, innerProtocol);
    }

    public GeneralizedSchnorrProtocol getInnerProtocol() {
        return innerProtocol;
    }

    public GroupElement getW() {
        return w;
    }

    @Override
    public SpecialHonestVerifierSimulator getSimulator() {
        return new InequalityProtocolSimulator(this);
    }

    /**
     * Update the value of the parameter w in the inner protocol and in this protocol as well
     * Used on verifier side when the value of w is extracted form the announcement in the verify.
     * Additionally, this is used in the simulator to set the simulated w to the protocol.
     *
     * @param w new value of w
     * @return the updated {@link InequalityProofProtocol}
     */
    public InequalityProofProtocol updateW(GroupElement w) {
        this.w = w;
        GeneralizedSchnorrProblem problemToUpdate = (GeneralizedSchnorrProblem) this.innerProtocol.getProblems()[1];
        problemToUpdate
                .setProblemEquation(new GroupElementEqualityExpression(new NumberGroupElementLiteral(w),
                        (ArithGroupElementExpression) problemToUpdate
                                .getProblemEquation().getRHS()));
        Problem[] updatedProblemArray = innerProtocol.getProblems();
        updatedProblemArray[1] = problemToUpdate;
        this.innerProtocol.setProblems(updatedProblemArray);
        return this;
    }

}
