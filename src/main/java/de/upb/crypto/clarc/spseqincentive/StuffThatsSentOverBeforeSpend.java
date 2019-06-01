package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.List;

public class StuffThatsSentOverBeforeSpend {
    de.upb.crypto.math.interfaces.structures.GroupElement dsid;
    List<GroupElement> ctraceRandomness;
    java.util.List<GroupElement> ctraceCiphertexts;
    Zp.ZpElement k;
    Zp.ZpElement gamma;
    int rho;
    List<GroupElement> blindedSigmaViStar;
    List<GroupElement> hViStar;
    List<GroupElement> blindedSigmaEskiStar;
    List<GroupElement> hEskiStar;
    GroupElement commitmentC0;
    de.upb.crypto.math.structures.zn.Zp.ZpElement c0;
    Zp.ZpElement c1;
    GroupElement Cpre0blinded /*Cpre0 * h6^Cpre0blinderVar*/;
    GroupElement Cpre0powU;
    GroupElement Cpre1PowU;
    Zp.ZpElement eskIsr;

    public StuffThatsSentOverBeforeSpend(GroupElement dsid, List<GroupElement> ctraceRandomness, List<GroupElement> ctraceCiphertexts, Zp.ZpElement k, Zp.ZpElement gamma, int rho, List<GroupElement> blindedSigmaViStar, List<GroupElement> hViStar, List<GroupElement> blindedSigmaEskiStar, List<GroupElement> hEskiStar, GroupElement commitmentC0, Zp.ZpElement c0, Zp.ZpElement c1, GroupElement cpre0blinded, GroupElement cpre0powU, GroupElement cpre1PowU, Zp.ZpElement eskIsr) {
        this.dsid = dsid;
        this.ctraceRandomness = ctraceRandomness;
        this.ctraceCiphertexts = ctraceCiphertexts;
        this.k = k;
        this.gamma = gamma;
        this.rho = rho;
        this.blindedSigmaViStar = blindedSigmaViStar;
        this.hViStar = hViStar;
        this.blindedSigmaEskiStar = blindedSigmaEskiStar;
        this.hEskiStar = hEskiStar;
        this.commitmentC0 = commitmentC0;
        this.c0 = c0;
        this.c1 = c1;
        Cpre0blinded = cpre0blinded;
        Cpre0powU = cpre0powU;
        Cpre1PowU = cpre1PowU;
        this.eskIsr = eskIsr;
    }
}
