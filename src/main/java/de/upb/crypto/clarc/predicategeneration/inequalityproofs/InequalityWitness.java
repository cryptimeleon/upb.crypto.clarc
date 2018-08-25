package de.upb.crypto.clarc.predicategeneration.inequalityproofs;

import de.upb.crypto.clarc.protocols.parameters.Witness;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.Objects;


/**
 * A Witness to the general construction for an inequality Proof (see Building Blocks construction 5.3 an
 * {@link InequalityProofProtocol}
 */
public class InequalityWitness implements Witness {

    @Represented(structure = "zp", recoveryMethod = Zp.ZpElement.RECOVERY_METHOD)
    private Zp.ZpElement x1, x2, x3;
    @Represented
    private Zp zp;
    @Represented
    private String name;


    public InequalityWitness(Zp.ZpElement x1, Zp.ZpElement x2, Zp.ZpElement x3, String name) {
        this.x1 = x1;
        this.x2 = x2;
        this.x3 = x3;
        this.zp = x1.getStructure();
        this.name = name;
    }

    public InequalityWitness(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    public Zp.ZpElement getX1() {
        return x1;
    }

    public void setX1(Zp.ZpElement x1) {
        this.x1 = x1;
    }

    public Zp.ZpElement getX2() {
        return x2;
    }

    public void setX2(Zp.ZpElement x2) {
        this.x2 = x2;
    }

    public Zp.ZpElement getX3() {
        return x3;
    }

    public void setX3(Zp.ZpElement x3) {
        this.x3 = x3;
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
        InequalityWitness witness = (InequalityWitness) o;
        return Objects.equals(getX1(), witness.getX1()) &&
                Objects.equals(getX2(), witness.getX2()) &&
                Objects.equals(getX3(), witness.getX3()) &&
                Objects.equals(zp, witness.zp) &&
                Objects.equals(getName(), witness.getName());
    }

    @Override
    public int hashCode() {

        return Objects.hash(getX1(), getX2(), getX3(), zp, getName());
    }
}
