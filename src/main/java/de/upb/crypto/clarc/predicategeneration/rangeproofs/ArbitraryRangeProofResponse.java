package de.upb.crypto.clarc.predicategeneration.rangeproofs;

import de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof.ZeroToUPowLRangeProofProtocol;
import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedArray;

import java.util.Arrays;

public class ArbitraryRangeProofResponse implements Response {
    @RepresentedArray(elementRestorer =
    @Represented(structure = "lowerBoundProtocol", recoveryMethod = Response.RECOVERY_METHOD))
    Response[] lowerBoundResponses;
    @RepresentedArray(elementRestorer =
    @Represented(structure = "upperBoundProtocol", recoveryMethod = Response.RECOVERY_METHOD))
    Response[] upperBoundResponses;

    SigmaProtocol lowerBoundProtocol, upperBoundProtocol;

    public ArbitraryRangeProofResponse(Response[] lowerBoundResponses, Response[] upperBoundResponses) {
        this.lowerBoundResponses = lowerBoundResponses;
        this.upperBoundResponses = upperBoundResponses;
    }

    public ArbitraryRangeProofResponse(Representation representation, ZeroToUPowLRangeProofProtocol lowerBoundProtocol,
                                       ZeroToUPowLRangeProofProtocol upperBoundProtocol) {
        this.lowerBoundProtocol = lowerBoundProtocol;
        this.upperBoundProtocol = upperBoundProtocol;
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ArbitraryRangeProofResponse that = (ArbitraryRangeProofResponse) o;
        return Arrays.equals(lowerBoundResponses, that.lowerBoundResponses) &&
                Arrays.equals(upperBoundResponses, that.upperBoundResponses);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(lowerBoundResponses);
        result = 31 * result + Arrays.hashCode(upperBoundResponses);
        return result;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }
}
