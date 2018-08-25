package de.upb.crypto.clarc.acs.protocols;

import de.upb.crypto.clarc.acs.issuer.credentials.CredentialIssuerPublicIdentity;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.SelectiveDisclosure;
import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import org.junit.jupiter.api.extension.*;

import java.util.ArrayList;
import java.util.List;

/**
 * This class describes the context used to invoke the generic test-cases of the {@link ProtocolFactoryTest}.
 * It contains additional protocols to test against while proving fulfillment of a policy as well as possession of
 * a valid master credential.
 */
public class ProtocolFactoryWithMasterCredExecutionContext extends ProtocolFactoryExecutionContext {
    final InteractiveThreeWayAoK invalidMasterCredProtocolProver;
    final InteractiveThreeWayAoK invalidMasterCredProtocolVerifier;

    ProtocolFactoryWithMasterCredExecutionContext(InteractiveThreeWayAoK fulfillingProtocolProver,
                                                  InteractiveThreeWayAoK anotherFulfillingProtocolProver,
                                                  InteractiveThreeWayAoK nonFulfillingProtocolProver,
                                                  InteractiveThreeWayAoK protocolVerifier,
                                                  SelectiveDisclosure[] selectiveDisclosures,
                                                  List<CredentialIssuerPublicIdentity> issuerPublicIdentities,
                                                  InteractiveThreeWayAoK invalidMasterCredProtocolProver,
                                                  InteractiveThreeWayAoK invalidMasterCredProtocolVerifier) {
        super(fulfillingProtocolProver, anotherFulfillingProtocolProver, nonFulfillingProtocolProver, protocolVerifier,
                selectiveDisclosures, issuerPublicIdentities);
        this.invalidMasterCredProtocolProver = invalidMasterCredProtocolProver;
        this.invalidMasterCredProtocolVerifier = invalidMasterCredProtocolVerifier;
    }


    @Override
    public List<Extension> getAdditionalExtensions() {
        // Ensure there is an additional registered resolver to resolve this class as parameter type
        List<Extension> extensions = new ArrayList<>(super.getAdditionalExtensions());
        extensions.add(new ParameterResolver() {
            @Override
            public boolean supportsParameter(ParameterContext parameterContext,
                                             ExtensionContext extensionContext) throws ParameterResolutionException {
                return parameterContext.getParameter().getType()
                        .equals(ProtocolFactoryWithMasterCredExecutionContext.class);
            }

            @Override
            public Object resolveParameter(ParameterContext parameterContext,
                                           ExtensionContext extensionContext) throws ParameterResolutionException {
                return ProtocolFactoryWithMasterCredExecutionContext.this;
            }
        });
        return extensions;
    }
}
