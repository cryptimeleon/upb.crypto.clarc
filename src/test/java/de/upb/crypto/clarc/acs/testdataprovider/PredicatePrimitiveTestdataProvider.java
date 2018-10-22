package de.upb.crypto.clarc.acs.testdataprovider;

import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.clarc.predicategeneration.equalityproofs.EqualityPublicParameterAdvancedProof;
import de.upb.crypto.clarc.predicategeneration.equalityproofs.EqualityPublicParameterUnknownValue;
import de.upb.crypto.clarc.predicategeneration.inequalityproofs.InequalityProofProtocol;
import de.upb.crypto.clarc.predicategeneration.inequalityproofs.InequalityPublicParameters;
import de.upb.crypto.clarc.predicategeneration.parametergeneration.EqualityParameterGen;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.ArbitraryRangeProofProtocol;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.ArbitraryRangeProofProtocolFactory;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof.ZeroToUPowLRangeProofProtocol;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof.ZeroToUPowLRangeProofProtocolFactory;
import de.upb.crypto.clarc.predicategeneration.setmembershipproofs.SetMembershipProofProtocol;
import de.upb.crypto.clarc.predicategeneration.setmembershipproofs.SetMembershipProtocolFactory;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulator;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorIdentity;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorValue;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentPair;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentScheme;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.craco.interfaces.abe.BigIntegerAttribute;
import de.upb.crypto.craco.interfaces.abe.RingElementAttribute;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;

public class PredicatePrimitiveTestdataProvider {

    private final PublicParameters clarcPublicParameters;
    private final PedersenCommitmentScheme commitmentScheme;
    private final PSCredential credential;

    private NguyenAccumulatorValue accumulatorValue;

    public PredicatePrimitiveTestdataProvider(PublicParameters clarcPublicParameters, PSCredential credential) {
        this.clarcPublicParameters = clarcPublicParameters;
        this.commitmentScheme = new PedersenCommitmentScheme(clarcPublicParameters.getSingleMessageCommitmentPublicParameters());
        this.credential = credential;

    }

    public PedersenCommitmentPair getCommitmentForAttribute(int positionInCredential) {
        return commitmentScheme.commit(new RingElementPlainText(credential
                .getAttributes()[positionInCredential].getZpRepresentation(clarcPublicParameters.getHashIntoZp())));
    }

    public Zp.ZpElement getZPRepresentationForAttrAtPos(int positionInCredential) {
        return credential.getAttributes()[positionInCredential]
                .getZpRepresentation(clarcPublicParameters.getHashIntoZp());

    }

    public EqualityPublicParameterUnknownValue getEqualityUnknownDlogPP(int positionInCredential,
                                                                        PedersenCommitmentPair commitment) {
        Zp.ZpElement alpha = credential.getAttributes()[positionInCredential].getZpRepresentation
                (clarcPublicParameters.getHashIntoZp());
        GroupElement g2 = clarcPublicParameters.getBilinearMap().getGT().getGenerator();

        return EqualityParameterGen.getEqualityPP(commitment.getCommitmentValue(),
                clarcPublicParameters.getSingleMessageCommitmentPublicParameters(), alpha, g2, positionInCredential,
                clarcPublicParameters.getZp());
    }

    public EqualityPublicParameterAdvancedProof getEqualityKnownDlogPP(int positionInCredential,
                                                                       PedersenCommitmentPair commitment) {
        Zp.ZpElement alpha = credential.getAttributes()[positionInCredential].getZpRepresentation
                (clarcPublicParameters.getHashIntoZp());

        return EqualityParameterGen.getEqualityPP(commitment.getCommitmentValue(),
                clarcPublicParameters.getSingleMessageCommitmentPublicParameters(), alpha, positionInCredential);
    }

    public InequalityProofProtocol getInequalityProtocol(int positionInCredential, String name,
                                                         BigInteger unequalValue) {
        PedersenCommitmentPair commitments = commitmentScheme.commit(new RingElementPlainText(credential
                .getAttributes()[positionInCredential].getZpRepresentation(clarcPublicParameters.getHashIntoZp())));

        Zp.ZpElement alpha = credential.getAttributes()[positionInCredential].getZpRepresentation
                (clarcPublicParameters.getHashIntoZp());

        //Create an y = g^s, where s <> value of attribute (therefore take value of attribute and add 1)
        GroupElement g2 = clarcPublicParameters.getBilinearMap().getGT().getGenerator();
        GroupElement y = g2.pow(unequalValue);


        GroupElement h = commitmentScheme.getPp().getH()[0];
        GroupElement g1 = commitmentScheme.getPp().getG();
        GroupElement commitment = commitments.getCommitmentValue().getCommitmentElement();
        de.upb.crypto.craco.interfaces.PublicParameters inequalityPP = new InequalityPublicParameters(g1, h, commitment, g2, y,
                positionInCredential, clarcPublicParameters.getZp());
        return new InequalityProofProtocol(commitments.getOpenValue().getRandomValue(),
                alpha, inequalityPP, name);
    }

    public SetMembershipProofProtocol getSetMembershipProtocol(int positionInCredential, String name) {
        Zp.ZpElement alpha = credential.getAttributes()[positionInCredential].getZpRepresentation
                (clarcPublicParameters.getHashIntoZp());

        //Create an set of Members
        Set<Zp.ZpElement> members = new HashSet<>();
        members.add(alpha);
        return getSetMembershipProtocol(positionInCredential, name, members);
    }

    public SetMembershipProofProtocol getSetMembershipProtocol(int positionInCredential, String name,
                                                               Set<Zp.ZpElement> members) {
        PedersenCommitmentPair commitments = commitmentScheme.commit(
                new RingElementPlainText(credential.getAttributes()[positionInCredential]
                        .getZpRepresentation(clarcPublicParameters.getHashIntoZp())));

        Zp.ZpElement alpha = credential.getAttributes()[positionInCredential].getZpRepresentation
                (clarcPublicParameters.getHashIntoZp());

        PedersenCommitmentValue commitment = commitments.getCommitmentValue();

        SetMembershipProtocolFactory factory = new SetMembershipProtocolFactory(commitment, commitmentScheme
                .getPp(), members, positionInCredential, clarcPublicParameters.getZp(),
                clarcPublicParameters.getNguyenAccumulatorPP(), name);
        return factory.getProverProtocol(commitments, alpha);
    }

    public ZeroToUPowLRangeProofProtocol getZeroToUPowLRangeProofProtocol(int positionInCredential, String name) {
        return getZeroToUPowLRangeProofProtocol(positionInCredential, name, BigInteger.valueOf(2), 5);
    }

    public ZeroToUPowLRangeProofProtocol getZeroToUPowLRangeProofProtocol(int positionInCredential,
                                                                          String name,
                                                                          BigInteger base,
                                                                          int exponent) {
        PedersenCommitmentPair commitments = commitmentScheme.commit(new RingElementPlainText(credential
                .getAttributes()[positionInCredential].getZpRepresentation(clarcPublicParameters.getHashIntoZp())));

        Attribute attrValue =
                credential.getAttributes()[positionInCredential].getAttributeValue();
        Zp.ZpElement alpha;
        if (attrValue instanceof BigIntegerAttribute) {
            alpha = clarcPublicParameters.getZp().createZnElement(((BigIntegerAttribute) attrValue).getAttribute());
        } else if (attrValue instanceof RingElementAttribute) {
            alpha = (Zp.ZpElement) ((RingElementAttribute) attrValue).getAttribute();
        } else {
            throw new IllegalArgumentException(" The given attribute has no ZP representation, thus hashing is " +
                    "applied and a range proof does not make sense");
        }

        PedersenCommitmentValue commitment = commitments.getCommitmentValue();
        ZeroToUPowLRangeProofProtocolFactory factory = new ZeroToUPowLRangeProofProtocolFactory(
                commitment, commitmentScheme.getPp(), base, exponent, positionInCredential,
                clarcPublicParameters.getZp(), clarcPublicParameters.getNguyenAccumulatorPP(), name);

        Set<NguyenAccumulatorIdentity> rangeValues = new HashSet<>();
        Zp zp = clarcPublicParameters.getZp();
        for (BigInteger counter = BigInteger.ZERO; counter.compareTo(base) < 0; counter = counter.add(BigInteger.ONE)) {
            rangeValues.add(new NguyenAccumulatorIdentity(zp.createZnElement(counter)));
        }

        NguyenAccumulator accumulator = new NguyenAccumulator(clarcPublicParameters.getNguyenAccumulatorPP());
        accumulatorValue = accumulator.create(rangeValues);
        return factory.getProverProtocol(commitments.getOpenValue().getRandomValue(), alpha);
    }

    public ArbitraryRangeProofProtocol getArbitraryRangeProofProtocol(int positionInCredential, String name) {
        return getArbitraryRangeProofProtocol(positionInCredential, name, BigInteger.valueOf(1),
                BigInteger.valueOf(30));
    }

    public ArbitraryRangeProofProtocol getArbitraryRangeProofProtocol(int positionInCredential,
                                                                      String name,
                                                                      BigInteger lowerBound,
                                                                      BigInteger upperBound) {
        Zp.ZpElement zpRepr =
                credential.getAttributes()[positionInCredential]
                        .getZpRepresentation(clarcPublicParameters.getHashIntoZp());
        PedersenCommitmentPair commitments = commitmentScheme.commit(new RingElementPlainText(zpRepr));

        Attribute attrValue =
                credential.getAttributes()[positionInCredential].getAttributeValue();
        Zp.ZpElement alpha;
        if (attrValue instanceof BigIntegerAttribute) {
            alpha = clarcPublicParameters.getZp().createZnElement(((BigIntegerAttribute) attrValue).getAttribute());
        } else if (attrValue instanceof RingElementAttribute) {
            alpha = (Zp.ZpElement) ((RingElementAttribute) attrValue).getAttribute();
        } else {
            throw new IllegalArgumentException(" The given attribute has no ZP representation, thus hashing is " +
                    "applied and a range proof does not make sense");
        }

        PedersenCommitmentValue commitment = commitments.getCommitmentValue();
        ArbitraryRangeProofProtocolFactory factory = new ArbitraryRangeProofProtocolFactory(
                commitment, commitmentScheme.getPp(), lowerBound, upperBound, positionInCredential,
                clarcPublicParameters.getZp(), clarcPublicParameters.getNguyenAccumulatorPP(), name);
        return factory.getProverProtocol(commitments, alpha);
    }

    public NguyenAccumulatorValue getAccumulatorValue() {
        return accumulatorValue;
    }

}
