package de.upb.crypto.clarc.acs.protocols.impl.clarc;

import de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens.ReviewToken;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.math.hash.impl.ByteArrayAccumulator;
import de.upb.crypto.math.interfaces.structures.GroupElement;

public class ComputeRatingPublicKeyAndItemHashHelper {
    public static GroupElement getHashedRatingPublicKeyAndItem(ReviewToken blindedToken, PublicParameters pp) {
        byte[] itemBytes = blindedToken.getItem().getData().getData();
        byte[] rpkBytes = blindedToken.getRatingIssuerPublicKey().getUniqueByteRepresentation();
        ByteArrayAccumulator dataToHash = new ByteArrayAccumulator();
        dataToHash.append(itemBytes);
        dataToHash.appendSeperator();
        dataToHash.append(rpkBytes);
        return (GroupElement) pp.getHashIntoGroup1().hashIntoStructure(dataToHash.extractBytes());
    }
}
