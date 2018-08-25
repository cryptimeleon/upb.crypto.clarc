package de.upb.crypto.clarc.acs.user;

import de.upb.crypto.clarc.acs.issuer.Issuable;
import de.upb.crypto.clarc.acs.issuer.IssueResponse;
import de.upb.crypto.clarc.acs.protocols.ProtocolParameters;
import de.upb.crypto.craco.commitment.interfaces.CommitmentValue;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

public abstract class InteractiveRequestIssuableProcess<IssuableType extends Issuable,
        IssuedObject extends StandaloneRepresentable> extends InteractiveProvingProcess {

    protected final InteractiveIssuingContext data;
    protected final IssuableType issuable;
    protected final IssueanceReceiver<IssuableType, IssuedObject> receiver;

    public InteractiveRequestIssuableProcess(InteractiveIssuingContext data,
                                             ProtocolParameters protocolParameters, IssuableType issuable,
                                             IssueanceReceiver<IssuableType, IssuedObject> receiver) {
        super(data.generateProtocol(), protocolParameters);
        this.data = data;
        this.issuable = issuable;
        this.receiver = receiver;
    }

    public IssuedObject receive(IssueResponse<IssuedObject> response) {
        return receiver.receive(response);
    }

    public CommitmentValue getUskCommitmentValue() {
        return data.getUskCommitmentValue();
    }

    public IssuableType getIssuable() {
        return issuable;
    }
}
