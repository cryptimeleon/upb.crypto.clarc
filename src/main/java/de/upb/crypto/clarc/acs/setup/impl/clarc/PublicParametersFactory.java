package de.upb.crypto.clarc.acs.setup.impl.clarc;

import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Identity;
import de.upb.crypto.clarc.acs.user.UserSecret;
import de.upb.crypto.clarc.protocols.damgardtechnique.DamgardTechnique;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulator;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorPublicParameters;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorPublicParametersGen;
import de.upb.crypto.craco.commitment.HashThenCommitCommitmentScheme;
import de.upb.crypto.craco.commitment.interfaces.CommitmentPair;
import de.upb.crypto.craco.commitment.interfaces.CommitmentValue;
import de.upb.crypto.craco.commitment.interfaces.OpenValue;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentScheme;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.craco.interfaces.signature.Signature;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.craco.sig.ps.PSPublicParameters;
import de.upb.crypto.math.factory.BilinearGroup;
import de.upb.crypto.math.factory.BilinearGroupFactory;
import de.upb.crypto.math.hash.impl.VariableOutputLengthHashFunction;
import de.upb.crypto.math.interfaces.hash.HashFunction;
import de.upb.crypto.math.interfaces.hash.HashIntoStructure;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.pairings.bn.BarretoNaehrigProvider;
import de.upb.crypto.math.pairings.mcl.MclBilinearGroupProvider;
import de.upb.crypto.math.structures.zn.HashIntoZp;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.Arrays;

public class PublicParametersFactory implements de.upb.crypto.clarc.acs.PublicParametersFactory {
    private boolean debugMode = false;
    private boolean lazygroups = false;
    private int securityParameter = 80;

    /**
     * Create a {@link NguyenAccumulator} whose parameters are defined by the systems
     * {@link PublicParameters}.
     * <br>
     * This {@link NguyenAccumulator} is expected to be used in range proofs in the ACS.
     *
     * @param clarcPublicParameters the public parameters of the system
     * @return {@link NguyenAccumulator} to be used in range proofs in the ACS.
     */
    public static NguyenAccumulator getAccumulator(PublicParameters clarcPublicParameters) {
        NguyenAccumulatorPublicParameters nguyenAccumulatorPP = clarcPublicParameters.getNguyenAccumulatorPP();
        return new NguyenAccumulator(nguyenAccumulatorPP);
    }

    /**
     * Set whether insecure public parameters are allowed to be generated
     *
     * @param debugMode true if insecure mappings are allowed, false if not.
     *                  ONLY USE THIS FOR TESTING!
     */
    public void setDebugMode(boolean debugMode) {
        this.debugMode = debugMode;
    }

    public void setLazygroups(boolean lazy) {
        this.lazygroups = lazy;
    }

    /**
     * Sets the security parameter for the public parameters
     *
     * @param securityParameter The security parameter of the resulting groups. Roughly corresponds to the complexity
     *                          of DLOG in G1, G2, GT in terms of equivalent-security symmetric encryption key length
     *                          (cf. http://www.keylength.com/)
     */
    public void setSecurityParameter(int securityParameter) {
        this.securityParameter = securityParameter;
    }

    /**
     * Creates a {@link PedersenCommitmentScheme} which is capable of committing to a single message at once.
     * The parameters for this scheme are defined by the systems {@link PublicParameters}.     *
     * <br>
     * This {@link PedersenCommitmentScheme} is expected to be used during every process which requires a
     * {@link CommitmentPair} ({@link CommitmentValue} and {@link OpenValue}) during the interaction with the ACS.
     * <br>
     * This can for example be used to create a {@link Identity} by committing to the {@link UserSecret}.
     *
     * @param clarcPublicParameters the public parameters of the system
     * @return {@link PedersenCommitmentScheme} which is capable of committing to a single message and creates the
     * {@link CommitmentPair} ({@link CommitmentValue} and {@link OpenValue}) to be used during the interactions
     * with the ACS
     */
    public static PedersenCommitmentScheme getSingleMessageCommitmentScheme(
            PublicParameters clarcPublicParameters) {
        return new PedersenCommitmentScheme(clarcPublicParameters.getSingleMessageCommitmentPublicParameters());
    }

    /**
     * Creates a {@link HashThenCommitCommitmentScheme} which is capable of committing to a arbitrary many message at
     * once.
     * The parameters for this scheme are defined by the systems {@link PublicParameters}.     *
     * <br>
     * This can for example be used to apply {@link DamgardTechnique} on the arbitrary amount of messages exchanged
     * by the internal protocol.
     * <br>
     *
     * @param clarcPublicParameters the public parameters of the system
     * @return {@link HashThenCommitCommitmentScheme} which is capable of committing to a arbitrary many message
     */
    public static HashThenCommitCommitmentScheme getMultiMessageCommitmentScheme(
            PublicParameters clarcPublicParameters) {
        return new HashThenCommitCommitmentScheme(getSingleMessageCommitmentScheme(clarcPublicParameters),
                clarcPublicParameters.getHashFunction());
    }

    /**
     * Creates a {@link PSExtendedSignatureScheme} whose parameters are defined by the systems
     * {@link PublicParameters}.
     * <br>
     * This {@link PSExtendedSignatureScheme} is expected to be used during every process which requires a
     * {@link Signature} during the interaction with the ACS.
     *
     * @param clarcPublicParameters the public parameters of the system
     * @return {@link PSExtendedSignatureScheme} to be used to create a {@link Signature} to be used during the
     * interactions with the ACS
     */
    public static PSExtendedSignatureScheme getSignatureScheme(PublicParameters clarcPublicParameters) {
        PSPublicParameters psPublicParameters = new PSPublicParameters(clarcPublicParameters.getBilinearMap());
        return new PSExtendedSignatureScheme(psPublicParameters);
    }

    @Override
    public PublicParameters create() {
        BilinearGroupFactory groupFactory = new BilinearGroupFactory(securityParameter);
        groupFactory.setDebugMode(debugMode);
        groupFactory.setRequirements(BilinearGroup.Type.TYPE_3, true, false, false);
        groupFactory.setLazyGroups(lazygroups);
        groupFactory.registerProvider(Arrays.asList(
                // new BarretoNaehrigNativeProvider(), //not yet publicly available
                new MclBilinearGroupProvider(),
                new BarretoNaehrigProvider()));

        BilinearGroup factory = groupFactory.createBilinearGroup();
        BilinearMap map = factory.getBilinearMap();
        HashIntoStructure hashIntoGroup1 = factory.getHashIntoG1();

        Zp zp = new Zp(map.getG1().size());
        final Group group = map.getG1();
        GroupElement g = group.getUniformlyRandomNonNeutral();
        GroupElement[] h = new GroupElement[]{group.getUniformlyRandomElement()};

        PedersenPublicParameters singleMessageCommitmentPP = new PedersenPublicParameters(g, h, group);

        HashFunction hashFunction = new VariableOutputLengthHashFunction((zp.getCharacteristic().bitLength() - 1) / 8); //cf Zn::injectiveValueOf.

        NguyenAccumulatorPublicParameters nguyenAccumulatorPP =
                new NguyenAccumulatorPublicParametersGen().setup(map, 20);

        System.out.println("Set up credential system on " + factory.getClass().getName());

        /**
         * The {@link VariableOutputLengthHashFunction}'s outputLength is chosen according to {@link Zp#injectiveValueOf(byte[])}
         */
        return new PublicParameters(
                map, singleMessageCommitmentPP, new HashIntoZp(zp), hashFunction, hashIntoGroup1, nguyenAccumulatorPP
        );
    }

}
