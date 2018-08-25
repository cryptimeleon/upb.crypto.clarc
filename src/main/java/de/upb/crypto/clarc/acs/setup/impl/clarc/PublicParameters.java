package de.upb.crypto.clarc.acs.setup.impl.clarc;


import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorPublicParameters;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.math.interfaces.hash.HashFunction;
import de.upb.crypto.math.interfaces.hash.HashIntoStructure;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.zn.HashIntoZp;
import de.upb.crypto.math.structures.zn.Zp;

import javax.annotation.CheckReturnValue;
import java.util.Objects;

public class PublicParameters implements de.upb.crypto.craco.interfaces.PublicParameters {
    @Represented
    private BilinearMap bilinearMap;
    @Represented
    private PedersenPublicParameters singleMessageCommitmentPublicParameters;

    @Represented
    private Zp zp;
    @Represented
    private HashIntoZp hashIntoZp;
    @Represented
    private HashFunction hashFunction;
    @Represented
    private HashIntoStructure hashIntoGroup1;
    @Represented
    private NguyenAccumulatorPublicParameters nguyenAccumulatorPP;

    public PublicParameters(BilinearMap map,
                            PedersenPublicParameters singleMessageCommitmentPublicParameters,
                            HashIntoZp hashIntoZp,
                            HashFunction hashFunction,
                            HashIntoStructure hashIntoGroup1,
                            NguyenAccumulatorPublicParameters nguyenAccumulatorPP) {
        this.bilinearMap = map;
        this.singleMessageCommitmentPublicParameters = singleMessageCommitmentPublicParameters;
        this.hashFunction = hashFunction;
        this.zp = new Zp(bilinearMap.getG1().size());
        this.hashIntoZp = hashIntoZp;
        this.hashIntoGroup1 = hashIntoGroup1;
        this.nguyenAccumulatorPP = nguyenAccumulatorPP;
    }

    public PublicParameters(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    @Override
    @CheckReturnValue
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    public BilinearMap getBilinearMap() {
        return bilinearMap;
    }

    public PedersenPublicParameters getSingleMessageCommitmentPublicParameters() {
        return singleMessageCommitmentPublicParameters;
    }

    public Zp getZp() {
        return zp;
    }

    public HashIntoZp getHashIntoZp() {
        return hashIntoZp;
    }

    public HashFunction getHashFunction() {
        return hashFunction;
    }

    public NguyenAccumulatorPublicParameters getNguyenAccumulatorPP() {
        return nguyenAccumulatorPP;
    }

    public void setNguyenAccumulatorPP(
            NguyenAccumulatorPublicParameters nguyenAccumulatorPP) {
        this.nguyenAccumulatorPP = nguyenAccumulatorPP;
    }

    public HashIntoStructure getHashIntoGroup1() {
        return hashIntoGroup1;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PublicParameters that = (PublicParameters) o;
        return Objects.equals(bilinearMap, that.bilinearMap) &&
                Objects.equals(singleMessageCommitmentPublicParameters, that.singleMessageCommitmentPublicParameters) &&
                Objects.equals(zp, that.zp) &&
                Objects.equals(hashIntoZp, that.hashIntoZp) &&
                Objects.equals(hashFunction, that.hashFunction) &&
                Objects.equals(hashIntoGroup1, that.hashIntoGroup1) &&
                Objects.equals(nguyenAccumulatorPP, that.nguyenAccumulatorPP);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                bilinearMap, singleMessageCommitmentPublicParameters, zp, hashIntoZp,
                hashFunction, hashIntoGroup1, nguyenAccumulatorPP
        );
    }
}
