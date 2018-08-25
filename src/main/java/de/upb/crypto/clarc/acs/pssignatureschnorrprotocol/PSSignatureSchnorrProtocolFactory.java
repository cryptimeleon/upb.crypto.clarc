package de.upb.crypto.clarc.acs.pssignatureschnorrprotocol;

import de.upb.crypto.clarc.acs.attributes.AttributeNameValuePair;
import de.upb.crypto.clarc.acs.attributes.AttributeSpace;
import de.upb.crypto.clarc.acs.subpolicyproving.SubPolicyProvingProtocolPublicParameters;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.clarc.protocols.expressions.arith.*;
import de.upb.crypto.clarc.protocols.expressions.comparison.GroupElementEqualityExpression;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.protocolfactory.GeneralizedSchnorrProtocolFactory;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentPair;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.craco.sig.ps.PSVerificationKey;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.HashIntoZp;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;

/**
 * This factory generates an instance of a generalized Schnorr protocol to proof knowledge of a randomized signature
 * and to proof, that the usk of a pseudonym is 1. the same as the usk used in the credential and 2., that the
 * pseudonym used is based on the usk. Therefore, the following relation is proven:
 * <p>
 * <p>
 * PK{ (d,usk,(a_i)_{i=1}^l, r ) :  nym = g_nym^d * h_nym ^usk <br>
 * AND <br>
 * e(sigma1',g~}^r * e(sigma1',Y0~)^usk * \prod_i=1}^{l} (e(sigma1',Yi~)^a_i = e(sigma2',g~) / e(sigma1',X~) } <br>
 * AND (i=l to l) <br>
 * C_i=g_{nym}^r_i * h_nym ^alpha_i
 * <p>
 * The names of the witnesses used are declared as constants.
 * In case that some attribute is disclosed, the proof for the Commitment is changed in the following way:<br>
 * C_i * (h_nym ^alpha_i)^-1 =g_{nym}^r_i
 */
public class PSSignatureSchnorrProtocolFactory {

    private static final int numberOfProblems = 2;

    public static final String SIGNATURE_RANDOM = "signatureRandom";
    public static final String USK = "usk";
    public static final String NYM_RANDOM = "nymRandom";

    private PedersenCommitmentValue nym;
    private PSSignature randomizedSignature;
    private Map<Integer, AttributeNameValuePair> disclosedElements;
    private PSExtendedVerificationKey key;
    private AttributeSpace attributeSpace;
    private List<PedersenCommitmentValue> commitmentsOnAttributes;
    private Zp zp;
    private HashIntoZp hashIntoZp;
    private BilinearMap bilinearMap;
    private PedersenPublicParameters singleMessageCommitmentPP;


    /**
     * Constructor, used by prover and verifier
     *
     * @param nym                       The pseudonym the prover is currently using
     * @param randomizedSignature       the randomized Signature created with the given pps, the key and the random
     *                                  value
     * @param signatureScheme           signature scheme used in the system
     * @param disclosedElements         A Map for elements needed to be disclosed. Therefore, the Map mapping form an
     *                                  int
     *                                  (the position of the revealed attribute in the attribute space (array) to the
     *                                  AttributeNameValuePair, containing the value that is required.
     * @param attributeSpace            the attribute space of the issuer who created the given signature
     * @param commitmentsOnAttributes   of the attribute-values
     * @param bilinearMap               bilinear map used by the system
     * @param singleMessageCommitmentPP public parameters to create pseudonyms in the system
     */
    public PSSignatureSchnorrProtocolFactory(PedersenCommitmentValue nym, PSSignature randomizedSignature,
                                             PSExtendedSignatureScheme signatureScheme, HashIntoZp hashIntoZp,
                                             Map<Integer, AttributeNameValuePair> disclosedElements,
                                             AttributeSpace attributeSpace,
                                             List<PedersenCommitmentValue> commitmentsOnAttributes,
                                             BilinearMap bilinearMap,
                                             PedersenPublicParameters singleMessageCommitmentPP) {
        this.nym = nym;
        this.randomizedSignature = randomizedSignature;
        this.disclosedElements = disclosedElements;
        this.commitmentsOnAttributes = commitmentsOnAttributes;
        this.attributeSpace = attributeSpace;
        this.zp = hashIntoZp.getTargetStructure();
        this.hashIntoZp = hashIntoZp;
        this.bilinearMap = bilinearMap;
        this.singleMessageCommitmentPP = singleMessageCommitmentPP;

        this.key = signatureScheme.getVerificationKey(attributeSpace.getIssuerPublicKey());
    }

    public PSSignatureSchnorrProtocolFactory(SubPolicyProvingProtocolPublicParameters subPolPP) {
        this(subPolPP.getPseudonym(), subPolPP.getRandomizedSignature(), subPolPP.getPsSignatureScheme(),
                subPolPP.getHashIntoZp(), subPolPP.getDisclosedElements(), subPolPP.getAttributeSpace(),
                subPolPP.getCommitmentsOnAttributes(), subPolPP.getBilinearMap(),
                subPolPP.getCommitmentScheme().getPp());
    }

    /**
     * Generates a Schnorr Protocol for a Prover.
     *
     * @param credential       the credential used
     * @param usk              usk of the user
     * @param nymRandom        the randomness used to create the pseudonym
     * @param signatureRandom, the random value used to create the randomized signature
     * @param commitmentPairs  for the commitments on the attributes
     * @return a generalizedSchnorrProtocol for a prover, containing the witnesses
     */
    public GeneralizedSchnorrProtocol getProverProtocol(PSCredential credential, Zp.ZpElement usk, Zp.ZpElement
            nymRandom, Zp.ZpElement signatureRandom, List<PedersenCommitmentPair> commitmentPairs) {

        List<String> attributeNames = Arrays.stream(credential.getAttributes()).map
                (AttributeNameValuePair::getAttributeName)
                .collect(Collectors.toList());
        // the "+2" is used, since the equations for the pseudonym and the signature are needed aswell
        GroupElementEqualityExpression[] problem = createProblem(attributeNames, attributeNames.size() + 2);
        // Additional elements in the wintess map (wintesses for disclosed elements) are ignored in the protocol
        // generation
        Map<String, Zp.ZpElement> witnessMap = createWitnessMap(credential, usk, nymRandom, signatureRandom,
                commitmentPairs);

        GeneralizedSchnorrProtocolFactory factory = new GeneralizedSchnorrProtocolFactory(problem, zp);
        return factory.createProverGeneralizedSchnorrProtocol(witnessMap);
    }


    /**
     * All  disclosed elements are part of the witness-array, since they are needed to prove that the commitments are
     * computed correctly
     * The value used is a Zp element, obtained by  the method
     * {@link AttributeNameValuePair#getZpRepresentation(HashIntoZp)}
     *
     * @param credential      needed to compute Hash(a_n),..., hash(a_n)
     * @param usk             user secret of the prover
     * @param nymRandom       random used to create the pseudonym
     * @param signatureRandom used to randomize the credential-signature
     * @param commitmentPairs used for the other euqations
     * @return a generalized Schnorr Witness containing all not disclosed elements
     */
    private Map<String, Zp.ZpElement> createWitnessMap(PSCredential credential, Zp.ZpElement usk,
                                                       Zp.ZpElement nymRandom,
                                                       Zp.ZpElement signatureRandom,
                                                       List<PedersenCommitmentPair> commitmentPairs) {
        Map<String, Zp.ZpElement> mapping = new HashMap<>();
        mapping.put(NYM_RANDOM, nymRandom);
        mapping.put(USK, usk);
        mapping.put(SIGNATURE_RANDOM, signatureRandom);
        for (int i = 0; i < commitmentPairs.size(); i++) {
            String name = credential.getAttributes()[i].getAttributeName();
            Zp.ZpElement valueInCred =
                    credential.getAttributes()[i].getZpRepresentation(hashIntoZp);
            boolean isCorrespondingPair = valueInCred.equals(commitmentPairs.get(i).getOpenValue().getMessages()[0]);
            if (!isCorrespondingPair) {
                throw new IllegalArgumentException("Can not compute the witnesses, sinc ethe ordering in the " +
                        "credential and the commitments is not equals!");
            }

            mapping.put(name, valueInCred);
            mapping.put(getNameForRandomOfAttribute(name), commitmentPairs.get(i).getOpenValue().getRandomValue());

        }
        return mapping;

    }

    /**
     * Generates a Schnorr Protocol for a Verifier
     *
     * @return a generalizedSchnorrProtocol for a verifier, containing NO witnesses
     */
    public GeneralizedSchnorrProtocol getVerifierProtocol() {
        List<String> attributeNames = attributeSpace.getDefinitions().stream().map
                (def -> def.getSuffixedAttributeName(key)
                ).collect(Collectors.toList());

        //the "+2" is used, since the equations for the pseudonym and the signature are needed aswell
        GroupElementEqualityExpression[] problem = createProblem(attributeNames, attributeNames.size() + 2);

        GeneralizedSchnorrProtocolFactory factory = new GeneralizedSchnorrProtocolFactory(problem, zp);
        return factory.createVerifierGeneralizedSchnorrProtocol();
    }


    /**
     * Generates two problems:
     * 1. A :=  e(sigma2',g~) / e(sigma1',X~) = e(sigma1',g~}^r * e(sigma1',Y0~)^usk * \prod_i=1}^{l} (e(sigma1',Yi~)
     * ^a_i
     * 2. nym = g^r * h ^usk
     * Since a_i is known for all disclosed elements, the equation is modified in the way, that (e(sigma1',Yi~)^a_i)
     * ^-1 is added to a and not present on the RHS
     *
     * @param attributeName    List of names of the attributes used in the credential
     * @param numberOfProblems number of problem equations used
     * @return an Array with a single problem, computed as described above.
     */
    private GroupElementEqualityExpression[] createProblem(List<String> attributeName, int numberOfProblems) {
        GroupElementEqualityExpression[] problemArray = new GroupElementEqualityExpression[numberOfProblems];

        //Compute e(sigma2',g~)
        GroupElement denominator =
                bilinearMap.apply(randomizedSignature.getGroup1ElementSigma2(), key.getGroup2ElementTildeG());
        //Compute   e(sigma1',X~)
        GroupElement nominator =
                bilinearMap.apply(randomizedSignature.getGroup1ElementSigma1(), key.getGroup2ElementTildeX());
        GroupElement nominatorInv = nominator.inv();
        //Set A = e(sigma2',g~) * (e(sigma1',X~))^-1
        GroupElement a1 = denominator.op(nominatorInv);

        //Create the first problem equation:
        problemArray[0] = createFirstProblemEquation(attributeName, a1);
        problemArray[1] = new GroupElementEqualityExpression(new NumberGroupElementLiteral(nym.getCommitmentElement()),
                createSecondProblemEquation());

        //Create the problem equations for the commitments
        //they are of the form: C_i=g_{nym}^r_i * h_nym ^alpha_i for i = 1, ..., l
        for (int i = 2; i < numberOfProblems; i++) {
            if (disclosedElements.containsKey(i - 2)) {
                // Element is disclosed, thus the proof needs to be changed to  C_i * (h_nym ^alpha_i)^-1 =g_{nym}^r_i
                problemArray[i] = createDisclosedCommitmentProblem(attributeName.get(i - 2),
                        commitmentsOnAttributes.get(i - 2), disclosedElements.get(i - 2));
            } else {
                // use default proof  C_i =g_{nym}^r_i * h_nym ^alpha_i
                problemArray[i] = createCommitmentProblem(attributeName.get(i - 2), commitmentsOnAttributes.get(i - 2));
            }
        }

        return problemArray;
    }

    /**
     * Creates problem equation for A :=  e(sigma2',g~) / e(sigma1',X~) = e(sigma1',g~}^r * e(sigma1',Y0~)^usk *
     * \prod_i=1}^{l} (e(sigma1',Yi~)
     * ^a_i
     *
     * @param attributeName list of attribute names
     * @param a1            :=  e(sigma2',g~) / e(sigma1',X~)
     * @return the equation
     */
    private GroupElementEqualityExpression createFirstProblemEquation(List<String> attributeName, GroupElement a1) {
        ProductGroupElementExpression rhs = new ProductGroupElementExpression();
        ArithGroupElementExpression sigma1Prime = new NumberGroupElementLiteral(randomizedSignature
                .getGroup1ElementSigma1());

        ArithGroupElementExpression gTilde = new NumberGroupElementLiteral(key.getGroup2ElementTildeG());
        rhs.addElement(
                new PowerGroupElementExpression(new PairingGroupElementExpression(bilinearMap, sigma1Prime, gTilde),
                        new ZnVariable(SIGNATURE_RANDOM)));
        ArithGroupElementExpression yiTilde0 = new NumberGroupElementLiteral(key.getGroup2ElementsTildeYi()[0]);
        rhs.addElement(new PowerGroupElementExpression(new PairingGroupElementExpression(bilinearMap, sigma1Prime,
                yiTilde0), new ZnVariable(USK)));

        for (int i = 0; i <= attributeName.size() - 1; i++) {
            //Index shift at getGroup2ElementsTildeYi, since the first element is for the usk
            ArithGroupElementExpression yiTildeI = new NumberGroupElementLiteral(key.getGroup2ElementsTildeYi()[i + 1]);
            if (isDisclosed(i, disclosedElements)) {
                //Modify A1 as follows: (e(sigma1',Yi~)^a_i)^-1 is added to A
                //Index shift at getGroup2ElementsTildeYi, since the first element is for the usk
                a1 = modifyA(randomizedSignature, key.getGroup2ElementsTildeYi()[i + 1],
                        disclosedElements.get(i).getZpRepresentation(hashIntoZp).getInteger(), a1);
            } else {
                rhs.addElement(new PowerGroupElementExpression(new PairingGroupElementExpression(bilinearMap,
                        sigma1Prime, yiTildeI), new ZnVariable(attributeName.get(i))));

            }
        }
        return new GroupElementEqualityExpression(new NumberGroupElementLiteral(a1), rhs); //TODO replace a1 with an appropriate expression that is more efficient to evaluate
    }


    /**
     * Computes A' = A * (e(sigma1',Yi~) ^a_i) ^-1 for a publicly known value of a_i
     *
     * @param signature randomized signature used by prover
     * @param yi        the group element Y_i~
     * @param hashOfAi  the hashed value (or normal value, if ai is a zp element, of attribute i in credential
     * @param a         current value of A
     * @return modified value of A
     */
    private GroupElement modifyA(PSSignature signature, GroupElement yi,
                                 BigInteger hashOfAi, GroupElement a) {
        //element = e(sigma1',Yi~) ^a_i
        GroupElement element = bilinearMap.apply(signature.getGroup1ElementSigma1(), yi,
                hashOfAi);
        //Compute A' = A * (e(sigma1',Yi~) ^a_i) ^-1 =  A * (element) ^-1
        a = a.op(element.inv());
        return a;
    }


    /**
     * Create second problem: A = nym = g^d * h^usk . This is done to generate a complete
     * description of the  problem, using all witnesses. In the calculation, the neutral elements are irrelevant
     *
     * @return problem description for second Problem equation
     */
    private ArithGroupElementExpression createSecondProblemEquation() {
        List<ArithGroupElementExpression> factors = new ArrayList<>();
        factors.add(new PowerGroupElementExpression(new NumberGroupElementLiteral(singleMessageCommitmentPP.getG()),
                new ZnVariable(NYM_RANDOM)));
        factors.add(new PowerGroupElementExpression(new NumberGroupElementLiteral(singleMessageCommitmentPP.getH()[0]),
                new ZnVariable(USK)));

        return new ProductGroupElementExpression(factors);
    }


    private GroupElementEqualityExpression createCommitmentProblem(String nameOfattribute,
                                                                   PedersenCommitmentValue c_i) {
        GroupElement g = singleMessageCommitmentPP.getG();
        GroupElement h = singleMessageCommitmentPP.getH()[0];

        ProductGroupElementExpression rhs = new ProductGroupElementExpression();

        rhs.addElement(new PowerGroupElementExpression(new NumberGroupElementLiteral(g),
                new ZnVariable(getNameForRandomOfAttribute(nameOfattribute))));
        rhs.addElement(new PowerGroupElementExpression(new NumberGroupElementLiteral(h),
                new ZnVariable(nameOfattribute)));
        return new GroupElementEqualityExpression(new NumberGroupElementLiteral(c_i.getCommitmentElement()), rhs);
    }

    private GroupElementEqualityExpression createDisclosedCommitmentProblem(String nameOfattribute,
                                                                            PedersenCommitmentValue c_i,
                                                                            AttributeNameValuePair disclosedElement) {
        GroupElement g = singleMessageCommitmentPP.getG();
        GroupElement h = singleMessageCommitmentPP.getH()[0];

        ProductGroupElementExpression rhs = new ProductGroupElementExpression();

        rhs.addElement(new PowerGroupElementExpression(new NumberGroupElementLiteral(g),
                new ZnVariable(getNameForRandomOfAttribute(nameOfattribute))));

        GroupElement hPowAlphaInv =
                h.pow(disclosedElement.getZpRepresentation(hashIntoZp)).inv();
        GroupElement lhs = c_i.getCommitmentElement().op(hPowAlphaInv);
        return new GroupElementEqualityExpression(new NumberGroupElementLiteral(lhs), rhs);
    }

    public PSVerificationKey getKey() {
        return key;
    }

    private boolean isDisclosed(int i, Map<Integer, AttributeNameValuePair> disclosedAttributes) {
        return disclosedAttributes.containsKey(i);
    }


    private String getNameForRandomOfAttribute(String nameOfattribute) {
        return "random_" + nameOfattribute;
    }
}
