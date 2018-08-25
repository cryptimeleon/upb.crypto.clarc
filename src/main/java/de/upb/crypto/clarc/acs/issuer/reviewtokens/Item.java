package de.upb.crypto.clarc.acs.issuer.reviewtokens;

import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

public class Item implements StandaloneRepresentable {
    @Represented
    private ByteArrayImplementation data;

    public Item(ByteArrayImplementation data) {
        this.data = data;
    }

    public Item(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    public ByteArrayImplementation getData() {
        return data;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Item item = (Item) o;
        return Objects.equals(data, item.data);
    }

    @Override
    public int hashCode() {
        return Objects.hash(data);
    }
}
