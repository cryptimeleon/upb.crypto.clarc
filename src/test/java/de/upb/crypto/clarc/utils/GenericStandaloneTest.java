package de.upb.crypto.clarc.utils;

import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.craco.interfaces.policy.PolicyFact;
import de.upb.crypto.craco.interfaces.signature.SignatureScheme;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.reflections.Reflections;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;


public abstract class GenericStandaloneTest implements ArgumentsProvider {
    protected abstract String getPackageName();

    protected abstract Collection<StandaloneTestParams> getStandaloneClasses();

    private Collection<StandaloneTestParams> collectStandaloneClasses() {
        Reflections reflection = new Reflections(getPackageName());
        // get all public classes that are subtypes of standalone representable
        Set<Class<? extends StandaloneRepresentable>> classes =
                reflection.getSubTypesOf(StandaloneRepresentable.class)
                        .stream().filter(clazz -> Modifier.isPublic(clazz.getModifiers()))
                        .collect(Collectors.toSet());
        // Standalone-detection
        classes.addAll(reflection.getSubTypesOf(PublicParameters.class));
        classes.addAll(reflection.getSubTypesOf(SignatureScheme.class));
        classes.addAll(reflection.getSubTypesOf(Policy.class));
        classes.addAll(reflection.getSubTypesOf(PolicyFact.class));
        Collection<StandaloneTestParams> toReturn = new ArrayList<>(getStandaloneClasses());

        for (StandaloneTestParams params : toReturn) {
            classes.remove(params.toTest);
        }

        // add remaining classes
        for (Class<? extends StandaloneRepresentable> c : classes) {
            if (!c.isInterface() && !Modifier.isAbstract(c.getModifiers())) {
                toReturn.add(new StandaloneTestParams(c, null));
            }
        }

        return toReturn;
    }

    @Override
    public Stream<? extends Arguments> provideArguments(ExtensionContext extensionContext) {
        return collectStandaloneClasses().stream().map(Arguments::of);
    }


    protected void runTestForConstructor(StandaloneTestParams params) throws NoSuchMethodException {
        Class<? extends StandaloneRepresentable> toTest = params.toTest;

        // tries to get the constructor that has Representation as class parameters
        Constructor<? extends StandaloneRepresentable> constructor = toTest.getConstructor(Representation.class);
        assertNotNull(constructor, "constructor");
    }

    protected void runCheckIfAllClassesOverrideEquals(StandaloneTestParams params) throws NoSuchMethodException {
        Class<? extends StandaloneRepresentable> toTest = params.toTest;

        Method equals = toTest.getMethod("equals", Object.class);
        // this is maybe not enough since it only asserts that any super
        // class overwrites equals
        assertNotEquals(equals.getDeclaringClass(), Object.class);
    }

    protected void runCheckForOverrideHashCode(StandaloneTestParams params) throws NoSuchMethodException {
        Class<? extends StandaloneRepresentable> toTest = params.toTest;

        Method hashCode = toTest.getMethod("hashCode");
        // this is maybe not enough since it only asserts that any super
        // class overwrites hashcode
        assertNotEquals(hashCode.getDeclaringClass(), Object.class,
                "Class " + toTest.getName() + " should override the hashCode() method");

    }

    protected void runTestRecreateRepresentable(
            StandaloneTestParams params) throws NoSuchMethodException, InvocationTargetException,
            IllegalAccessException, InstantiationException {
        Class<? extends StandaloneRepresentable> toTest = params.toTest;
        Object instance = params.instance;
        // tests whether the deserialization of the serialized object equals the
        // original object
        if (instance == null) {
            Logger.getLogger(GenericStandaloneTest.class.getName()).severe("cannot get instance for the object");
            fail("No object given for " + toTest.getName());
        } else {
            Constructor<? extends StandaloneRepresentable> constructor = toTest.getConstructor(Representation.class);
            assertNotNull(constructor, "constructor");
            Representation repr = (Representation) toTest.getMethod("getRepresentation").invoke(instance);
            assertEquals(instance, constructor.newInstance(repr));
        }
    }

    /**
     * Ensures that each derivation of this base class implements the test for constructors
     * <p>
     * The deriving class needs to implement this method which must invoke
     * {@link GenericStandaloneTest#runTestForConstructor} and define the attributes
     * {@link org.junit.jupiter.params.ParameterizedTest} and {@link org.junit.jupiter.params.provider.ArgumentsSource}
     * (with the derived class as input).
     *
     * @param params Here the params object which is received by the parameterized test run must be passed in.
     */
    @SuppressWarnings("unused")
    protected abstract void testForConstructor(StandaloneTestParams params) throws NoSuchMethodException;

    /**
     * Ensures that each derivation of this base class implements the test for hash code overrides
     * <p>
     * The deriving class needs to implement this method which must invoke
     * {@link GenericStandaloneTest#runCheckForOverrideHashCode(StandaloneTestParams)} and define the attributes
     * {@link org.junit.jupiter.params.ParameterizedTest} and {@link org.junit.jupiter.params.provider.ArgumentsSource}
     * (with the derived class as input).
     *
     * @param params Here the params object which is received by the parameterized test run must be passed in.
     */
    @SuppressWarnings("unused")
    protected abstract void checkForOverrideHashCode(StandaloneTestParams params) throws NoSuchMethodException;

    /**
     * Ensures that each derivation of this base class implements the test for equals overrides
     * <p>
     * The deriving class needs to implement this method which must invoke
     * {@link GenericStandaloneTest#runCheckIfAllClassesOverrideEquals(StandaloneTestParams)} and define the attributes
     * {@link org.junit.jupiter.params.ParameterizedTest} and {@link org.junit.jupiter.params.provider.ArgumentsSource}
     * (with the derived class as input).
     *
     * @param params Here the params object which is received by the parameterized test run must be passed in.
     */
    @SuppressWarnings("unused")
    protected abstract void checkIfAllClassesOverrideEquals(StandaloneTestParams params) throws NoSuchMethodException;

    /**
     * Ensures that each derivation of this base class implements the test for recreation of representables
     * <p>
     * The deriving class needs to implement this method which must invoke
     * {@link GenericStandaloneTest#runTestRecreateRepresentable(StandaloneTestParams)} and define the attributes
     * {@link org.junit.jupiter.params.ParameterizedTest} and {@link org.junit.jupiter.params.provider.ArgumentsSource}
     * (with the derived class as input).
     *
     * @param params Here the params object which is received by the parameterized test run must be passed in.
     */
    @SuppressWarnings("unused")
    protected abstract void testRecreateRepresentable(
            StandaloneTestParams params) throws NoSuchMethodException, InvocationTargetException,
            IllegalAccessException, InstantiationException;
}