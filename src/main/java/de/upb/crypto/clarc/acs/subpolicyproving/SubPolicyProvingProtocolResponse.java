package de.upb.crypto.clarc.acs.subpolicyproving;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedArray;

import java.util.Arrays;

public class SubPolicyProvingProtocolResponse implements Response {

    @RepresentedArray(elementRestorer = @Represented(structure = "pSSignatureSchnorrProtocol", recoveryMethod =
            Response.RECOVERY_METHOD))
    private Response[] responsesPSSignatureSchnorrProtocol;
    @RepresentedArray(elementRestorer = @Represented(structure = "poPk", recoveryMethod = Response.RECOVERY_METHOD))
    private Response[] responsesPoPKProtocol;

    private SigmaProtocol pSSignatureSchnorrProtocol;
    private SigmaProtocol poPk;

    public SubPolicyProvingProtocolResponse(Response[] responsesPSSignatureSchnorrProtocol,
                                            Response[] responsesPoPKProtocol) {
        this.responsesPSSignatureSchnorrProtocol = responsesPSSignatureSchnorrProtocol;
        this.responsesPoPKProtocol = responsesPoPKProtocol;
    }


    public SubPolicyProvingProtocolResponse(Representation representation, SigmaProtocol pSSignatureSchnorrProtocol,
                                            SigmaProtocol poPK) {
        this.pSSignatureSchnorrProtocol = pSSignatureSchnorrProtocol;
        this.poPk = poPK;
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    public Response[] getResponsesPSSignatureSchnorrProtocol() {
        return responsesPSSignatureSchnorrProtocol;
    }

    public void setResponsesPSSignatureSchnorrProtocol(Response[] responsesPSSignatureSchnorrProtocol) {
        this.responsesPSSignatureSchnorrProtocol = responsesPSSignatureSchnorrProtocol;
    }

    public Response[] getResponsesPoPKProtocol() {
        return responsesPoPKProtocol;
    }

    public void setResponsesPoPKProtocol(Response[] responsesPoPKProtocol) {
        this.responsesPoPKProtocol = responsesPoPKProtocol;
    }

    /**
     * The representation of this object. Used for serialization
     *
     * @return a Representation or null if the representedTypeName suffices to instantiate an equal object again
     * @see Representation
     */
    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SubPolicyProvingProtocolResponse that = (SubPolicyProvingProtocolResponse) o;
        return Arrays.equals(getResponsesPSSignatureSchnorrProtocol(), that.getResponsesPSSignatureSchnorrProtocol()) &&
                Arrays.equals(getResponsesPoPKProtocol(), that.getResponsesPoPKProtocol());
    }

    @Override
    public int hashCode() {

        int result = Arrays.hashCode(getResponsesPSSignatureSchnorrProtocol());
        result = 31 * result + Arrays.hashCode(getResponsesPoPKProtocol());
        return result;
    }
}
