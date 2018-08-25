package de.upb.crypto.clarc.acs.subpolicyproving;

import de.upb.crypto.clarc.acs.attributes.AttributeNameValuePair;
import de.upb.crypto.clarc.acs.attributes.AttributeSpace;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.SecretSharingSchemeProviders;
import de.upb.crypto.craco.commitment.interfaces.CommitmentValue;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentScheme;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.craco.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.craco.secretsharing.SecretSharingSchemeProvider;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.craco.sig.ps.PSSignatureScheme;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedList;
import de.upb.crypto.math.serialization.annotations.RepresentedMap;
import de.upb.crypto.math.structures.zn.HashIntoZp;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Public parameter that works for {@link SubPolicyProvingProtocol}.
 * They contain the policy, the system's {@link PublicParameters}, the {@link PSSignatureScheme},
 * the {@link CommitmentValue} (Pseudonym) of the user, the list of disclosed elements, the commitments on the
 * attributes and the randomized signature.
 * <br>
 * Note that commitment on Attributes or the randomized signature may be empty / initialized with invalid signature
 */
public class SubPolicyProvingProtocolPublicParameters implements PublicParameters {

    @Represented
    private ThresholdPolicy policy;
    @Represented
    private Zp zp;
    @Represented
    private PSExtendedSignatureScheme psSignatureScheme;
    @Represented
    private PedersenCommitmentScheme commitmentScheme;
    @Represented
    private HashIntoZp hashIntoZp;
    @Represented
    private PedersenCommitmentValue pseudonym;
    @Represented
    private SecretSharingSchemeProvider linearSecretSharingSchemeProvider;

    @RepresentedMap(keyRestorer = @Represented, valueRestorer = @Represented)
    private Map<Integer, AttributeNameValuePair> disclosedElements;

    @Represented
    private AttributeSpace attributeSpace;
    @RepresentedList(elementRestorer = @Represented)
    private List<PedersenCommitmentValue> commitmentsOnAttributes;
    @Represented(structure = "psSignatureScheme", recoveryMethod = PSSignature.RECOVERY_METHOD)
    private PSSignature randomizedSignature;
    @Represented
    private BilinearMap bilinearMap;

    public SubPolicyProvingProtocolPublicParameters(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    /**
     * @param commitmentScheme  commitment scheme of the system to craete commitments during the proofs
     * @param psSignatureScheme used to create the credential
     * @param pseudonym         used by the user
     * @param disclosedElements known in advance
     * @param attributeSpace    of the credential
     * @param policy            needed to be fulfilled
     * @param hashIntoZp        hash function into the Zp of the system
     * @param bilinearMap       bilinear map of the system
     */
    public SubPolicyProvingProtocolPublicParameters(PedersenCommitmentScheme commitmentScheme,
                                                    PSExtendedSignatureScheme psSignatureScheme,
                                                    PedersenCommitmentValue pseudonym,
                                                    Map<Integer, AttributeNameValuePair> disclosedElements,
                                                    AttributeSpace attributeSpace, ThresholdPolicy policy,
                                                    HashIntoZp hashIntoZp,
                                                    BilinearMap bilinearMap) {
        this(commitmentScheme, psSignatureScheme, pseudonym, disclosedElements, attributeSpace, policy,
                SecretSharingSchemeProviders.SHAMIR, hashIntoZp, bilinearMap);
    }

    /**
     * @param commitmentScheme                  commitment scheme of the system to craete commitments during the proofs
     * @param psSignatureScheme                 used to create the credential
     * @param pseudonym                         used by the user
     * @param disclosedElements                 known in advance
     * @param attributeSpace                    of the credential
     * @param policy                            needed to be fulfilled
     * @param linearSecretSharingSchemeProvider the {@link SecretSharingSchemeProvider} to be used to create
     *                                          linearSecretSharingScheme instances for proofs of partial knowledge.
     *                                          Should be taken from {@link SecretSharingSchemeProviders}
     * @param hashIntoZp                        hash function into the Zp of the system
     * @param bilinearMap                       bilinear map of the system
     */
    public SubPolicyProvingProtocolPublicParameters(PedersenCommitmentScheme commitmentScheme,
                                                    PSExtendedSignatureScheme psSignatureScheme,
                                                    PedersenCommitmentValue pseudonym,
                                                    Map<Integer, AttributeNameValuePair> disclosedElements,
                                                    AttributeSpace attributeSpace, ThresholdPolicy policy,
                                                    SecretSharingSchemeProvider linearSecretSharingSchemeProvider,
                                                    HashIntoZp hashIntoZp,
                                                    BilinearMap bilinearMap) {
        this.zp = hashIntoZp.getTargetStructure();
        this.psSignatureScheme = psSignatureScheme;
        this.pseudonym = pseudonym;
        this.disclosedElements = disclosedElements;
        this.attributeSpace = attributeSpace;
        this.policy = policy;
        this.linearSecretSharingSchemeProvider = linearSecretSharingSchemeProvider;
        this.bilinearMap = bilinearMap;
        this.commitmentsOnAttributes = new ArrayList<>();
        this.randomizedSignature = null;
        this.commitmentScheme = commitmentScheme;
        this.hashIntoZp = hashIntoZp;
    }

    public Zp getZp() {
        return zp;
    }

    public PSExtendedSignatureScheme getPsSignatureScheme() {
        return psSignatureScheme;
    }

    public PedersenCommitmentValue getPseudonym() {
        return pseudonym;
    }

    public Map<Integer, AttributeNameValuePair> getDisclosedElements() {
        return disclosedElements;
    }

    public AttributeSpace getAttributeSpace() {
        return attributeSpace;
    }

    public List<PedersenCommitmentValue> getCommitmentsOnAttributes() {
        return commitmentsOnAttributes;
    }

    public void setCommitmentsOnAttributes(List<PedersenCommitmentValue> commitmentsOnAttributes) {
        this.commitmentsOnAttributes = commitmentsOnAttributes;
    }

    public PSSignature getRandomizedSignature() {
        return randomizedSignature;
    }

    public void setRandomizedSignature(PSSignature randomizedSignature) {
        this.randomizedSignature = randomizedSignature;
    }

    public ThresholdPolicy getPolicy() {
        return policy;
    }

    public SecretSharingSchemeProvider getLinearSecretSharingSchemeProvider() {
        return linearSecretSharingSchemeProvider;
    }

    public PedersenCommitmentScheme getCommitmentScheme() {
        return commitmentScheme;
    }

    public HashIntoZp getHashIntoZp() {
        return hashIntoZp;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SubPolicyProvingProtocolPublicParameters that = (SubPolicyProvingProtocolPublicParameters) o;
        return Objects.equals(policy, that.policy) &&
                Objects.equals(getZp(), that.getZp()) &&
                Objects.equals(getPsSignatureScheme(), that.getPsSignatureScheme()) &&
                Objects.equals(getPseudonym(), that.getPseudonym()) &&
                Objects.equals(getDisclosedElements(), that.getDisclosedElements()) &&
                Objects.equals(getAttributeSpace(), that.getAttributeSpace()) &&
                Objects.equals(getCommitmentsOnAttributes(), that.getCommitmentsOnAttributes()) &&
                Objects.equals(getRandomizedSignature(), that.getRandomizedSignature());
    }

    @Override
    public int hashCode() {
        return Objects.hash(policy, getZp(), getPsSignatureScheme(), getPseudonym(),
                getDisclosedElements(), getAttributeSpace(), getCommitmentsOnAttributes(), getRandomizedSignature());
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    public void setDisclosedElements(Map<Integer, AttributeNameValuePair> disclosedElements) {
        this.disclosedElements = disclosedElements;
    }

    public BilinearMap getBilinearMap() {
        return bilinearMap;
    }
}
