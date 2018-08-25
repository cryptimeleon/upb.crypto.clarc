package de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedArray;

import java.util.Arrays;

/**
 * This {@link Response} is specifically used during the execution of a {@link PolicyProvingWithMasterCredProtocol}.
 * It contains the {@link Response} of both inner protocol.
 */
public class PolicyProvingWithMasterCredResponse implements Response {

    private PolicyProvingProtocol policyProvingProtocol;
    private SigmaProtocol masterCredProvingProtocol;

    @RepresentedArray(elementRestorer = @Represented(structure = "policyProvingProtocol",
            recoveryMethod = Response.RECOVERY_METHOD))
    private Response[] policyResponses;
    @RepresentedArray(elementRestorer = @Represented(structure = "masterCredProvingProtocol",
            recoveryMethod = Response.RECOVERY_METHOD))
    private Response[] masterCredResponses;


    public PolicyProvingWithMasterCredResponse(
            Response[] policyResponses,
            Response[] masterCredResponses) {
        this.policyResponses = policyResponses;
        this.masterCredResponses = masterCredResponses;
    }

    public PolicyProvingWithMasterCredResponse(Representation representation,
                                               PolicyProvingProtocol policyProvingProtocol,
                                               SigmaProtocol masterCredProvingProtocol) {
        this.policyProvingProtocol = policyProvingProtocol;
        this.masterCredProvingProtocol = masterCredProvingProtocol;
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    public Response[] getPolicyResponses() {
        return policyResponses;
    }

    public Response[] getMasterCredResponses() {
        return masterCredResponses;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PolicyProvingWithMasterCredResponse response = (PolicyProvingWithMasterCredResponse) o;
        return Arrays.equals(policyResponses, response.policyResponses) &&
                Arrays.equals(masterCredResponses, response.masterCredResponses);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(policyResponses);
        result = 31 * result + Arrays.hashCode(masterCredResponses);
        return result;
    }
}
