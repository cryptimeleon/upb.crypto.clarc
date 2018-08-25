package de.upb.crypto.clarc.acs.serialization.classes;

import de.upb.crypto.clarc.acs.protocols.proveNym.ProveNymProtocol;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Identity;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.testdataprovider.IssuerTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.ParameterTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.PredicatePrimitiveTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.UserAndSystemManagerTestdataProvider;
import de.upb.crypto.clarc.predicategeneration.equalityproofs.EqualityPublicParameterAdvancedProof;
import de.upb.crypto.clarc.predicategeneration.equalityproofs.EqualityPublicParameterUnknownValue;
import de.upb.crypto.clarc.predicategeneration.inequalityproofs.InequalityProofProtocol;
import de.upb.crypto.clarc.predicategeneration.inequalityproofs.InequalityPublicParameters;
import de.upb.crypto.clarc.predicategeneration.inequalityproofs.InequalityWitness;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.ArbitraryRangeProofProtocol;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.ArbitraryRangeProofPublicParameters;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof.RangeProofWitness;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof.ZeroToUPowLRangeProofProtocol;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof.ZeroToUPowLRangeProofPublicParameters;
import de.upb.crypto.clarc.predicategeneration.setmembershipproofs.SetMembershipProofProtocol;
import de.upb.crypto.clarc.predicategeneration.setmembershipproofs.SetMembershipPublicParameters;
import de.upb.crypto.clarc.predicategeneration.setmembershipproofs.SetMembershipWitness;
import de.upb.crypto.clarc.utils.StandaloneTestParams;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentPair;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;

public class PredicateParams {

    public static Collection<StandaloneTestParams> get() {

        ParameterTestdataProvider clarcProvider = new ParameterTestdataProvider();
        UserAndSystemManagerTestdataProvider userProvider =
                new UserAndSystemManagerTestdataProvider(clarcProvider.getPublicParameters());
        IssuerTestdataProvider issuerProvider = new IssuerTestdataProvider(clarcProvider.getPublicParameters(),
                clarcProvider.getSignatureScheme(), userProvider.getUserSecret());
        PredicatePrimitiveTestdataProvider predicateProvider =
                new PredicatePrimitiveTestdataProvider(clarcProvider.getPublicParameters(),
                        issuerProvider.getCredentialWitfDefaultAttributeSpace());

        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();

        PedersenCommitmentPair comEq = predicateProvider.getCommitmentForAttribute(0);

        toReturn.add(new StandaloneTestParams(EqualityPublicParameterUnknownValue.class,
                predicateProvider.getEqualityUnknownDlogPP(0, comEq)));
        toReturn.add(new StandaloneTestParams(EqualityPublicParameterAdvancedProof.class,
                predicateProvider.getEqualityKnownDlogPP(0, comEq)));

        InequalityProofProtocol inequalityProtocol = predicateProvider.getInequalityProtocol(0, "name",
                predicateProvider.getZPRepresentationForAttrAtPos(0).getInteger().add(BigInteger.ONE));
        inequalityProtocol.generateAnnouncements();
        toReturn.add(new StandaloneTestParams(InequalityProofProtocol.class, inequalityProtocol));
        toReturn.add(new StandaloneTestParams(InequalityWitness.class, inequalityProtocol.getWitnesses()[0]));
        toReturn.add(new StandaloneTestParams(InequalityPublicParameters.class,
                inequalityProtocol.getPublicParameters()));

        SetMembershipProofProtocol setMembershipProtocol = predicateProvider.getSetMembershipProtocol(0, "name");
        setMembershipProtocol.generateAnnouncements();
        toReturn.add(new StandaloneTestParams(SetMembershipProofProtocol.class, setMembershipProtocol));
        toReturn.add(new StandaloneTestParams(SetMembershipWitness.class, setMembershipProtocol.getWitnesses()[0]));
        toReturn.add(new StandaloneTestParams(SetMembershipPublicParameters.class,
                setMembershipProtocol.getPublicParameters()));

        ZeroToUPowLRangeProofProtocol zeroToUPowLRangeProofProtocol =
                predicateProvider.getZeroToUPowLRangeProofProtocol(0, "name");
        toReturn.add(new StandaloneTestParams(ZeroToUPowLRangeProofProtocol.class, zeroToUPowLRangeProofProtocol));
        toReturn.add(new StandaloneTestParams(RangeProofWitness.class,
                zeroToUPowLRangeProofProtocol.getWitnesses()[0]));
        toReturn.add(new StandaloneTestParams(ZeroToUPowLRangeProofPublicParameters.class,
                zeroToUPowLRangeProofProtocol.getPublicParameters()));

        ArbitraryRangeProofProtocol arbitraryRangeProofProtocol =
                predicateProvider.getArbitraryRangeProofProtocol(0, "name");
        toReturn.add(new StandaloneTestParams(ArbitraryRangeProofProtocol.class, arbitraryRangeProofProtocol));
        toReturn.add(new StandaloneTestParams(RangeProofWitness.class, arbitraryRangeProofProtocol
                .getWitnesses()[0]));
        toReturn.add(new StandaloneTestParams(ArbitraryRangeProofPublicParameters.class, arbitraryRangeProofProtocol
                .getPublicParameters()));


        Identity identity = userProvider.getIdentity();
        PublicParameters clarcPP = clarcProvider.getPublicParameters();
        Zp.ZpElement usk = identity.getPseudonymSecret().getMessages()[0];
        Zp.ZpElement nymRandom = identity.getPseudonymSecret().getRandomValue();
        ProveNymProtocol proveNymProtocol =
                new ProveNymProtocol(nymRandom, usk, clarcPP.getSingleMessageCommitmentPublicParameters(),
                        identity.getPseudonym().getCommitmentValue());
        toReturn.add(new StandaloneTestParams(ProveNymProtocol.class, proveNymProtocol));

        return toReturn;
    }
}