package de.upb.crypto.clarc.acs.issuer.reviewtokens.impl.clarc;

import de.upb.crypto.clarc.acs.issuer.reviewtokens.HashOfItem;
import de.upb.crypto.clarc.acs.issuer.reviewtokens.Item;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.math.structures.zn.HashIntoZp;
import de.upb.crypto.math.structures.zn.Zp;

public class HashOfItemHelper {
    public static HashOfItem getHashOfItemFromBytes(PublicParameters pp, byte... bytes) {
        Item item = new Item(new ByteArrayImplementation(bytes));
        HashIntoZp hashIntoZp = pp.getHashIntoZp();
        Zp.ZpElement hash = hashIntoZp.hashIntoStructure(bytes);
        return new HashOfItem(hash, item);
    }
}
