package de.upb.crypto.clarc.acs.serialization;

import de.upb.crypto.clarc.acs.serialization.classes.*;
import de.upb.crypto.clarc.utils.GenericStandaloneTest;
import de.upb.crypto.clarc.utils.StandaloneTestParams;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Collection;

class AcsStandaloneTest extends GenericStandaloneTest {

    @Override
    protected String getPackageName() {
        return "de.upb.crypto.clarc.acs";
    }


    @Override
    protected Collection<StandaloneTestParams> getStandaloneClasses() {
        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();

        toReturn.addAll(Params.get());
        toReturn.addAll(ActorsParams.get());
        toReturn.addAll(FixedProtocolsParams.get());
        toReturn.addAll(PredicateParams.get());
        toReturn.addAll(PolicyParams.get());
        toReturn.addAll(NonInteractiveParams.get());
        toReturn.addAll(ReputationSystemParams.get());
        toReturn.addAll(PolicyProofProtocols.get());

        // building blocks
        toReturn.addAll(AttributeParams.get());
        toReturn.addAll(PSCredentialParams.get());
        return toReturn;
    }

    @Override
    @ParameterizedTest
    @ArgumentsSource(AcsStandaloneTest.class)
    public void testForConstructor(StandaloneTestParams params) throws NoSuchMethodException {
        runTestForConstructor(params);
    }

    @Override
    @ParameterizedTest
    @ArgumentsSource(AcsStandaloneTest.class)
    public void checkForOverrideHashCode(StandaloneTestParams params) throws NoSuchMethodException {
        runCheckForOverrideHashCode(params);
    }

    @Override
    @ParameterizedTest
    @ArgumentsSource(AcsStandaloneTest.class)
    public void checkIfAllClassesOverrideEquals(StandaloneTestParams params) throws NoSuchMethodException {
        runCheckIfAllClassesOverrideEquals(params);
    }

    @Override
    @ParameterizedTest
    @ArgumentsSource(AcsStandaloneTest.class)
    public void testRecreateRepresentable(
            StandaloneTestParams params) throws NoSuchMethodException, InvocationTargetException,
            IllegalAccessException, InstantiationException {
        runTestRecreateRepresentable(params);
    }
}
