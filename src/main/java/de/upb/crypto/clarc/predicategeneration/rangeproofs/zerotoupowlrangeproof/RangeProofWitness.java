package de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof;

import de.upb.crypto.clarc.protocols.parameters.Witness;
import de.upb.crypto.math.interfaces.structures.RingElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.Objects;

/**
 * Witness to the range proof for interval [0,u^l] (by Camenisch, Chaabouni, and Shelat [CCs08])
 */
public class RangeProofWitness implements Witness {
    @Represented
    private String name;

    /**
     * The value committed to in the commitment,
     * which is supposed to lie within the range.
     */
    @Represented(structure = "zp", recoveryMethod = RingElement.RECOVERY_METHOD)
    private Zp.ZpElement alpha;

    /**
     * Open value for the commitment.
     */
    @Represented(structure = "zp", recoveryMethod = RingElement.RECOVERY_METHOD)
    private Zp.ZpElement openValue;

    @Represented
    private Zp zp;

    public RangeProofWitness(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    public RangeProofWitness(String name, Zp.ZpElement alpha,
                             Zp.ZpElement openValue) {
        this.name = name;
        this.alpha = alpha;
        this.openValue = openValue;
        this.zp = alpha.getStructure();
    }

    @Override
    public String getName() {
        return this.name;
    }

    public Zp.ZpElement getAlpha() {
        return alpha;
    }

    public Zp.ZpElement getOpenValue() {
        return openValue;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RangeProofWitness that = (RangeProofWitness) o;
        return Objects.equals(name, that.name) &&
                Objects.equals(alpha, that.alpha) &&
                Objects.equals(openValue, that.openValue);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, alpha, openValue);
    }
}
