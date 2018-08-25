package de.upb.crypto.clarc.predicategeneration.parametergeneration;

import de.upb.crypto.clarc.predicategeneration.equalityproofs.EqualityPublicParameterAdvancedProof;
import de.upb.crypto.clarc.predicategeneration.equalityproofs.EqualityPublicParameterUnknownValue;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.PredicateTypePrimitive;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

public class EqualityParameterGen {

    /**
     * Generate  for an equality-proof (Section 5.1.1), where s is equal to a <b>not publicly known value</b><br>
     * <p>
     * Create a proof for generator^alpha = generator ^ unknownDLog,
     * where alpha is the value inside the commitment.
     *
     * @param commitmentOnAttribute     to proof that the value is equal
     * @param pedersenPP                used to generate the commitment on the attributes
     * @param unknownDLog               the value, for that it needs to be shown that it is equal to the value. Will
     *                                  be hidden in the pp, since only g^unknownDLog is stored
     * @param generator                 used for the proof of committedValue equal to unknownDLog
     * @param positionOfFirstCommitment in the attribute space / credential
     * @param zp                        Zp used in the system
     * @return the specified equalityPP without commitment
     */
    public static EqualityPublicParameterUnknownValue getEqualityPP(PedersenCommitmentValue commitmentOnAttribute,
                                                                    PedersenPublicParameters pedersenPP,
                                                                    Zp.ZpElement unknownDLog,
                                                                    GroupElement generator,
                                                                    int positionOfFirstCommitment,
                                                                    Zp zp) {
        GroupElement commitment = commitmentOnAttribute.getCommitmentElement();
        GroupElement equalHiddenValue = generator.pow(unknownDLog);
        return new EqualityPublicParameterUnknownValue(pedersenPP, commitment, generator, equalHiddenValue,
                positionOfFirstCommitment, zp, PredicateTypePrimitive.EQUALITY_DLOG);
    }

    /**
     * Generate  for an equality-proof (Section 5.1.1), where s is equal to a <b>not publicly known value</b><br>
     * <p>
     * Create a proof for generator^alpha = generator ^ unknownDLog,
     * where alpha is the value inside the commitment.
     *
     * @param pedersenPP                used to generate the commitment on the attributes
     * @param unknownDLog               the value, for that it needs to be shown that it is equal to the value. Will
     *                                  be hidden in the pp, since only g^unknownDLog is stored
     * @param generator                 used for the proof of committedValue equal to unknownDLog
     * @param positionOfFirstCommitment in the attribute space / credential
     * @param zp                        Zp used in the system
     * @return the specified equalityPP without commitment
     */
    public static EqualityPublicParameterUnknownValue getEqualityPP(PedersenPublicParameters pedersenPP,
                                                                    Zp.ZpElement unknownDLog,
                                                                    GroupElement generator,
                                                                    int positionOfFirstCommitment,
                                                                    Zp zp) {
        GroupElement equalHiddenValue = generator.pow(unknownDLog);
        return new EqualityPublicParameterUnknownValue(pedersenPP, generator, equalHiddenValue,
                positionOfFirstCommitment, zp, PredicateTypePrimitive.EQUALITY_DLOG);
    }

    /**
     * Generate  for an equality-proof (Section 5.1.2), where alpha is equal to a <b>publicly known value knownDLog</b>
     * <p>
     * Create a proof for generator^alpha = generator ^ knownDLog,
     * where alpha is the value inside the commitment.
     *
     * @param pedersenPP                used to generate the commitment on the attributes
     * @param knownDLog                 the value, for that it needs to be shown that it is equal to the value.
     *                                  is publicly known thus stored in the PP object.
     * @param positionOfFirstCommitment in the attribute space / credential
     * @return the specified equalityPP without commitment
     */
    public static EqualityPublicParameterAdvancedProof getEqualityPP(PedersenPublicParameters pedersenPP,
                                                                     Zp.ZpElement knownDLog,
                                                                     int positionOfFirstCommitment) {
        return new EqualityPublicParameterAdvancedProof(pedersenPP, knownDLog, positionOfFirstCommitment,
                PredicateTypePrimitive.EQUALITY_PUBLIC_VALUE);
    }

    /**
     * Generate  for an equality-proof (Section 5.1.2), where alpha is equal to a <b>publicly known value knownDLog</b>
     * <p>
     * Create a proof for generator^alpha = generator ^ knownDLog,
     * where alpha is the value inside the commitment.
     *
     * @param commitmentOnAttribute     to proof that the value is equal
     * @param pedersenPP                used to generate the commitment on the attributes
     * @param knownDLog                 the value, for that it needs to be shown that it is equal to the value.
     *                                  is publicly known thus stored in the PP object.
     * @param positionOfFirstCommitment in the attribute space / credential
     * @return the specified equalityPP without commitment
     */
    public static EqualityPublicParameterAdvancedProof getEqualityPP(PedersenCommitmentValue commitmentOnAttribute,
                                                                     PedersenPublicParameters pedersenPP,
                                                                     Zp.ZpElement knownDLog,
                                                                     int positionOfFirstCommitment) {
        EqualityPublicParameterAdvancedProof epp =
                new EqualityPublicParameterAdvancedProof(pedersenPP, knownDLog, positionOfFirstCommitment,
                        PredicateTypePrimitive.EQUALITY_PUBLIC_VALUE);
        epp.setCommitment(commitmentOnAttribute.getCommitmentElement());
        return epp;
    }

    /**
     * Generate  for an equality-proof (Section 5.1.3), where iot is shown that two commitments contain the same value
     * <p>
     * Create a proof for generator^alpha1 = generator ^ alpha2
     * where alpha1 and alpha2 are the values inside the commitment.
     *
     * @param pedersenPP                 used to generate the commitment on the attributes
     * @param positionOfFirstCommitment  in the attribute space / credential
     * @param positionofSecondCommitment in the attribute space / credential
     * @param zp                         Zp used in the system
     * @return the specified equalityPP without commitment
     */
    public static EqualityPublicParameterAdvancedProof getEqualityPP(PedersenPublicParameters pedersenPP,
                                                                     int positionOfFirstCommitment,
                                                                     int positionofSecondCommitment,
                                                                     Zp zp) {
        return new EqualityPublicParameterAdvancedProof(pedersenPP, zp.getZeroElement(),
                positionOfFirstCommitment, positionofSecondCommitment,
                PredicateTypePrimitive.EQUALITY_2_ATTRIBUTES);
    }

    /**
     * Generate  for an equality-proof (Section 5.1.3), where iot is shown that two commitments contain the same value
     * <p>
     * Create a proof for generator^alpha1 = generator ^ alpha2
     * where alpha1 and alpha2 are the values inside the commitment.
     *
     * @param commitmentOnFirstAttribute  for alpha 1
     * @param commitmentOnSecondAttribute for alpha2
     * @param pedersenPP                  used to generate the commitment on the attributes
     * @param positionOfFirstCommitment   in the attribute space / credential
     * @param positionofSecondCommitment  in the attribute space / credential
     * @param zp                          Zp used in the system
     * @return the specified equalityPP without commitment
     */
    public static EqualityPublicParameterAdvancedProof getEqualityPP(PedersenCommitmentValue commitmentOnFirstAttribute,
                                                                     PedersenCommitmentValue
                                                                             commitmentOnSecondAttribute,
                                                                     PedersenPublicParameters pedersenPP,
                                                                     int positionOfFirstCommitment,
                                                                     int positionofSecondCommitment,
                                                                     Zp zp) {
        EqualityPublicParameterAdvancedProof epp =
                new EqualityPublicParameterAdvancedProof(pedersenPP, zp.getZeroElement(),
                        positionOfFirstCommitment, positionofSecondCommitment,
                        PredicateTypePrimitive.EQUALITY_2_ATTRIBUTES);
        // Compute C = C1 \op (C2)^-1
        epp.setCommitment(commitmentOnFirstAttribute.getCommitmentElement()
                .op(commitmentOnSecondAttribute.getCommitmentElement().inv()));
        return epp;
    }
}
