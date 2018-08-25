package de.upb.crypto.clarc.acs.protocols;

import de.upb.crypto.clarc.acs.issuer.credentials.CredentialIssuerPublicIdentity;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.SelectiveDisclosure;
import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import org.junit.jupiter.api.extension.*;

import java.util.Collections;
import java.util.List;

/**
 * This class describes the context used to invoke the generic test-cases of the {@link ProtocolFactoryTest}.
 */
public class ProtocolFactoryExecutionContext implements TestTemplateInvocationContext {
    final InteractiveThreeWayAoK fulfillingProtocolProver;
    final InteractiveThreeWayAoK anotherFulfillingProtocolProver;
    final InteractiveThreeWayAoK nonFulfillingProtocolProver;
    final InteractiveThreeWayAoK protocolVerifier;
    final SelectiveDisclosure[] selectiveDisclosures;
    final List<CredentialIssuerPublicIdentity> issuerPublicIdentities;

    ProtocolFactoryExecutionContext(
            InteractiveThreeWayAoK fulfillingProtocolProver,
            InteractiveThreeWayAoK anotherFulfillingProtocolProver,
            InteractiveThreeWayAoK nonFulfillingProtocolProver,
            InteractiveThreeWayAoK protocolVerifier,
            SelectiveDisclosure[] selectiveDisclosures,
            List<CredentialIssuerPublicIdentity> issuerPublicIdentities) {
        this.fulfillingProtocolProver = fulfillingProtocolProver;
        this.anotherFulfillingProtocolProver = anotherFulfillingProtocolProver;
        this.nonFulfillingProtocolProver = nonFulfillingProtocolProver;
        this.protocolVerifier = protocolVerifier;
        this.selectiveDisclosures = selectiveDisclosures;
        this.issuerPublicIdentities = issuerPublicIdentities;
    }

    @Override
    public List<Extension> getAdditionalExtensions() {
        // Ensure there is a registered resolver to resolve this class as parameter type
        return Collections.singletonList(new ParameterResolver() {
            @Override
            public boolean supportsParameter(ParameterContext parameterContext,
                                             ExtensionContext extensionContext) throws ParameterResolutionException {
                return parameterContext.getParameter().getType().equals(ProtocolFactoryExecutionContext.class);
            }

            @Override
            public Object resolveParameter(ParameterContext parameterContext,
                                           ExtensionContext extensionContext) throws ParameterResolutionException {
                return ProtocolFactoryExecutionContext.this;
            }
        });
    }
}
