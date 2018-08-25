package de.upb.crypto.clarc.utils;

import de.upb.crypto.math.serialization.StandaloneRepresentable;

/**
 * Parameters for an execution of the standalone representable test The test
 * requires an instance of a standalone representable. Every class implementing
 * this interface should have a constructor that recreates an Representation
 * into an Object. By definition the recreated object and the provided object
 * should be the same (i.e. equals yields true).
 */
public class StandaloneTestParams {
    final Class<? extends StandaloneRepresentable> toTest;
    final Object instance;

    public StandaloneTestParams(Class<? extends StandaloneRepresentable> toTest, Object instance) {
        this.toTest = toTest;
        this.instance = instance;
    }

    public StandaloneTestParams(StandaloneRepresentable instance) {
        this(instance.getClass(), instance);
    }

    @Override
    public String toString() {
        return toTest.getName();
    }
}
