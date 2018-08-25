package de.upb.crypto.clarc.acs.subpolicyproving;

import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.clarc.protocols.parameters.Witness;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentPair;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedList;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.List;
import java.util.Objects;

public class SubPolicyProvingProtocolWitness implements Witness {

    @Represented(structure = "zp", recoveryMethod = Zp.ZpElement.RECOVERY_METHOD)
    private Zp.ZpElement signatureRandom;
    @Represented
    private Zp zp;
    @Represented
    private String name;
    @RepresentedList(elementRestorer = @Represented)
    private List<PedersenCommitmentPair> commitmentsOnAttributes;
    @Represented
    private PSExtendedSignatureScheme scheme;
    @Represented
    private PSCredential credential;
    @Represented(structure = "zp", recoveryMethod = Zp.ZpElement.RECOVERY_METHOD)
    private Zp.ZpElement nymRandom;
    @Represented(structure = "zp", recoveryMethod = Zp.ZpElement.RECOVERY_METHOD)
    private Zp.ZpElement usk;


    public SubPolicyProvingProtocolWitness(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    /**
     * Creates a full witness
     *
     * @param signatureRandom         value used for randomizing the signature of the credential
     * @param commitmentsOnAttributes of the credential used
     * @param credential              used to prove the policy
     * @param usk                     of the user
     * @param nymRandom               used to randomize the usk
     * @param name                    of the witness
     * @param scheme                  the scheme used for the credential
     */
    public SubPolicyProvingProtocolWitness(Zp.ZpElement signatureRandom,
                                           List<PedersenCommitmentPair> commitmentsOnAttributes,
                                           PSCredential credential,
                                           Zp.ZpElement usk, Zp.ZpElement nymRandom, String name,
                                           PSExtendedSignatureScheme scheme) {
        this.signatureRandom = signatureRandom;
        this.commitmentsOnAttributes = commitmentsOnAttributes;
        this.credential = credential;
        this.usk = usk;
        this.nymRandom = nymRandom;
        this.zp = nymRandom.getStructure();
        this.scheme = scheme;
        this.name = name;
    }


    public List<PedersenCommitmentPair> getCommitmentsOnAttributes() {
        return commitmentsOnAttributes;
    }

    public void setCommitmentsOnAttributes(List<PedersenCommitmentPair> commitmentsOnAttributes) {
        this.commitmentsOnAttributes = commitmentsOnAttributes;
    }

    public PSCredential getCredential() {
        return credential;
    }

    public void setCredential(PSCredential credential) {
        this.credential = credential;
    }

    public Zp.ZpElement getUsk() {
        return usk;
    }

    public Zp.ZpElement getNymRandom() {
        return nymRandom;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Zp.ZpElement getSignatureRandom() {
        return signatureRandom;
    }

    public void setSignatureRandom(Zp.ZpElement signatureRandom) {
        this.signatureRandom = signatureRandom;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);

    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SubPolicyProvingProtocolWitness that = (SubPolicyProvingProtocolWitness) o;
        return Objects.equals(getSignatureRandom(), that.getSignatureRandom()) &&
                Objects.equals(zp, that.zp) &&
                Objects.equals(getName(), that.getName()) &&
                Objects.equals(getCommitmentsOnAttributes(), that.getCommitmentsOnAttributes()) &&
                Objects.equals(scheme, that.scheme) &&
                Objects.equals(getCredential(), that.getCredential()) &&
                Objects.equals(getNymRandom(), that.getNymRandom()) &&
                Objects.equals(getUsk(), that.getUsk());
    }

    @Override
    public int hashCode() {
        return Objects
                .hash(getSignatureRandom(), zp, getName(), getCommitmentsOnAttributes(), scheme, getCredential(),
                        getNymRandom(), getUsk());
    }
}
