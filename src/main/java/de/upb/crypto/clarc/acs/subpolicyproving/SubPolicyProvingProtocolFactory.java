package de.upb.crypto.clarc.acs.subpolicyproving;

import de.upb.crypto.clarc.acs.attributes.AttributeNameValuePair;
import de.upb.crypto.clarc.acs.attributes.AttributeSpace;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.SecretSharingSchemeProviders;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentScheme;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.craco.secretsharing.SecretSharingSchemeProvider;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.structures.zn.HashIntoZp;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.ArrayList;
import java.util.Map;

/**
 * A factory creating SubPolicyProvingProtocol protocols
 */
public class SubPolicyProvingProtocolFactory {

    private SubPolicyProvingProtocolPublicParameters subPolicyProvingProtocolPublicParameters;

    /**
     * This factory is used to create SubPolicyProvingProtocol protocols, see {@link SubPolicyProvingProtocol}
     *
     * @param commitmentScheme  commitment scheme used in the system
     * @param psSignatureScheme of the Issuer used to sign the credential
     * @param pseudonym         of the user
     * @param attributeSpace    of the used credential
     * @param disclosedElements Elements that should be disclosed
     * @param policy            {@link ThresholdPolicy} which fulfillment is to be proven during protocol execution
     * @param hashIntoZp        hash function into Zp used in the system
     * @param bilinearMap       bilinear map of the system
     */
    public SubPolicyProvingProtocolFactory(PedersenCommitmentScheme commitmentScheme,
                                           PSExtendedSignatureScheme psSignatureScheme,
                                           PedersenCommitmentValue pseudonym, AttributeSpace attributeSpace,
                                           Map<Integer, AttributeNameValuePair> disclosedElements,
                                           ThresholdPolicy policy, HashIntoZp hashIntoZp, BilinearMap bilinearMap) {
        this(commitmentScheme, psSignatureScheme, pseudonym, attributeSpace, disclosedElements, policy,
                SecretSharingSchemeProviders.SHAMIR, hashIntoZp, bilinearMap);
    }

    /**
     * This factory is used to create SubPolicyProvingProtocol protocols, see {@link SubPolicyProvingProtocol}
     *
     * @param commitmentScheme     commitment scheme used in the system
     * @param psSignatureScheme    of the Issuer used to sign the credential
     * @param pseudonym            of the user
     * @param attributeSpace       of the used credential
     * @param disclosedElements    Elements that should be disclosed
     * @param policy               {@link ThresholdPolicy} which fulfillment is to be proven
     * @param lsssInstanceProvider {@link SecretSharingSchemeProvider} to be used to create lsss instances for
     *                             proofs of partial knowledge.
     *                             Should be taken from {@link SecretSharingSchemeProviders}
     * @param hashIntoZp           hash function into Zp used in the system
     * @param bilinearMap          bilinear map of the system
     */
    public SubPolicyProvingProtocolFactory(PedersenCommitmentScheme commitmentScheme,
                                           PSExtendedSignatureScheme psSignatureScheme,
                                           PedersenCommitmentValue pseudonym, AttributeSpace attributeSpace,
                                           Map<Integer, AttributeNameValuePair> disclosedElements,
                                           ThresholdPolicy policy,
                                           SecretSharingSchemeProvider lsssInstanceProvider,
                                           HashIntoZp hashIntoZp, BilinearMap bilinearMap) {
        subPolicyProvingProtocolPublicParameters =
                new SubPolicyProvingProtocolPublicParameters(commitmentScheme, psSignatureScheme, pseudonym,
                        disclosedElements, attributeSpace, policy, lsssInstanceProvider, hashIntoZp, bilinearMap);
    }

    /**
     * Returns a SubPolicyProvingProtocol Protocol for the prover
     *
     * @param credential used to prove the policy
     * @param usk        of the user
     * @param nymRandom  used to randomize the usk
     * @return Protocol instance for the prover side including all witnesses needed to prove fulfillment of the given
     * {@link ThresholdPolicy}
     */
    public SubPolicyProvingProtocol getProverProtocol(PSCredential credential, Zp.ZpElement usk,
                                                      Zp.ZpElement nymRandom) {
        Zp.ZpElement signatureRandom = subPolicyProvingProtocolPublicParameters.getZp().getUniformlyRandomElement();
        SubPolicyProvingProtocolWitness subPolicyProvingProtocolWitness =
                new SubPolicyProvingProtocolWitness(signatureRandom, new ArrayList<>(), credential, usk, nymRandom,
                        SubPolicyProvingProtocol.getNameForWitnesses(this.subPolicyProvingProtocolPublicParameters
                                .getPolicy()), this.subPolicyProvingProtocolPublicParameters.getPsSignatureScheme());

        return new SubPolicyProvingProtocol(subPolicyProvingProtocolWitness,
                this.subPolicyProvingProtocolPublicParameters);
    }

    /**
     * Return new SubPolicyProvingProtocol Protocol for the verifier
     *
     * @return Protocol instance for the verifier side with all information needed to verify fulfillment of the given
     * {@link ThresholdPolicy}
     */
    public SubPolicyProvingProtocol getVerifieryProtocol() {
        return new SubPolicyProvingProtocol(SubPolicyProvingProtocol.getNameForWitnesses(
                this.subPolicyProvingProtocolPublicParameters.getPolicy()), subPolicyProvingProtocolPublicParameters);
    }
}
