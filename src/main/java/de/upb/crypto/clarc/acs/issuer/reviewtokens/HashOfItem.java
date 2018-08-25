package de.upb.crypto.clarc.acs.issuer.reviewtokens;

import de.upb.crypto.clarc.acs.issuer.Issuable;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.Objects;

/**
 * This class is used to issue review token. It extends the class {@link Issuable}, which is used in the issuance
 * protocol.
 */
public class HashOfItem extends Issuable {
    @Represented
    private Zp zp;
    @Represented(structure = "zp", recoveryMethod = Zp.ZpElement.RECOVERY_METHOD)
    private Zp.ZpElement hash;
    @Represented
    private Item item;

    public HashOfItem(Zp.ZpElement hash, Item item) {
        this.hash = hash;
        this.zp = hash.getStructure();
        this.item = item;
    }

    public HashOfItem(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    public Zp.ZpElement getHash() {
        return hash;
    }

    public Item getItem() {
        return item;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        HashOfItem that = (HashOfItem) o;
        return Objects.equals(zp, that.zp) &&
                Objects.equals(hash, that.hash);
    }

    @Override
    public int hashCode() {
        return Objects.hash(zp, hash);
    }
}
