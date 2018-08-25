package de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof;

import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.math.serialization.ListRepresentation;
import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.Arrays;

public class ZeroToUPowLRangeProofResponse implements Response {
    Response[] innerProtocolResponses;

    public ZeroToUPowLRangeProofResponse(Response[] innerProtocolResponses) {
        this.innerProtocolResponses = innerProtocolResponses;
    }

    public ZeroToUPowLRangeProofResponse(Representation representation, Zp zp) {
        innerProtocolResponses = representation.list()
                .stream()
                .map(r -> GeneralizedSchnorrProtocol.recreateResponse(r, zp))
                .toArray(Response[]::new);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ZeroToUPowLRangeProofResponse
                that = (ZeroToUPowLRangeProofResponse) o;
        return Arrays.equals(innerProtocolResponses, that.innerProtocolResponses);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(innerProtocolResponses);
    }

    @Override
    public Representation getRepresentation() {
        return new ListRepresentation(Arrays.stream(innerProtocolResponses)
                .map(Representable::getRepresentation)
                .toArray(Representation[]::new));
    }
}
