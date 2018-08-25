package de.upb.crypto.clarc.predicategeneration.setmembershipproofs;

import de.upb.crypto.clarc.protocols.parameters.Witness;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.Objects;

/**
 * A Witness to the general construction for an inequality Proof (see Building Blocks construction 5.3 and
 * {@link SetMembershipProofProtocol}
 */
public class SetMembershipWitness implements Witness {

    @Represented(structure = "zp", recoveryMethod = Zp.ZpElement.RECOVERY_METHOD)
    private Zp.ZpElement r, alpha, z;
    @Represented
    private Zp zp;
    @Represented
    private String name;

    public SetMembershipWitness(Zp.ZpElement r, Zp.ZpElement alpha, Zp.ZpElement z, String name) {
        this.r = r;
        this.alpha = alpha;
        this.z = z;
        this.zp = r.getStructure();
        this.name = name;
    }

    public SetMembershipWitness(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    public Zp.ZpElement getR() {
        return r;
    }

    public Zp.ZpElement getAlpha() {
        return alpha;
    }

    public Zp.ZpElement getZ() {
        return z;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SetMembershipWitness
                witness = (SetMembershipWitness) o;
        return Objects.equals(getR(), witness.getR()) &&
                Objects.equals(getAlpha(), witness.getAlpha()) &&
                Objects.equals(getZ(), witness.getZ()) &&
                Objects.equals(zp, witness.zp) &&
                Objects.equals(getName(), witness.getName());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getR(), getAlpha(), getZ(), zp, getName());
    }
}