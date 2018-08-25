package de.upb.crypto.clarc.acs.pseudonym.impl.clarc;

import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParametersFactory;
import de.upb.crypto.clarc.acs.user.impl.clarc.UserSecret;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentPair;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentScheme;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;

public class IdentityFactory implements de.upb.crypto.clarc.acs.pseudonym.IdentityFactory {
    @Override
    public Identity create(de.upb.crypto.craco.interfaces.PublicParameters pp, de.upb.crypto.clarc.acs.user.UserSecret usk) {
        PublicParameters clarcPP = (PublicParameters) pp;
        UserSecret clarcUsk = (UserSecret) usk;

        if (!(clarcPP.getBilinearMap().getG1().size().equals(clarcUsk.getUsk().getStructure().size()))) {
            throw new IllegalArgumentException("The given USK does not match the PP, since the usk is from Z_" +
                    clarcUsk.getUsk().getStructure().size() + "but the Zp needed as exponent in the PP is Z_" +
                    clarcPP.getBilinearMap().getG1().size());
        }

        PedersenCommitmentScheme commitmentScheme =
                PublicParametersFactory.getSingleMessageCommitmentScheme(clarcPP);

        PedersenCommitmentPair commitment =
                commitmentScheme.commit(new MessageBlock(new RingElementPlainText(clarcUsk.getUsk())));
        return new Identity(commitment);
    }
}
