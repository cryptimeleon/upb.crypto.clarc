package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentPair;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentScheme;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalCipherText;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalEncryption;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalPlainText;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalPublicKey;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSPublicParameters;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

import java.lang.reflect.Array;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * A prover instance of the Spend <-> Deduct protocol.
 */
public class SpendInstance  extends CPreComProofInstance{
	Zp.ZpElement k;
	IncentiveToken token;
	SigmaProtocol schnorrProtocol;
	StuffThatsSentOverBeforeSpend stuff;

	public SpendInstance(IncentiveSystemPublicParameters pp, IncentiveProviderPublicKey pk, IncentiveUserKeyPair keyPair, Zp.ZpElement k, IncentiveToken token, IncentiveUser.CPreComProofValues cPreComProofValues, Zp.ZpElement eskisr) {
		super(pp, pk, keyPair, cPreComProofValues);
		this.pp = pp;
		this.pk = pk;
		this.k = k;
		this.token = token;
		this.eskisr = eskisr;
	}


	public static final BigInteger BASE = BigInteger.valueOf(1000);
	public static final int rho(BigInteger p) {
		return (int) (Math.ceil(p.bitLength() / (double) BASE.bitLength()) + 2);
	}
	public static final int VMAX_EXPONENT = 3; //vmax is BASE^{VMAX_EXPONENT} s.t. I can write vmax

	public static List<Zp.ZpElement> getUaryRepresentationOf(Zp.ZpElement value) {
		BigInteger p = value.getStructure().size();
		int rho = rho(p);

		if (VMAX_EXPONENT >= rho-1) {
			throw new RuntimeException("vmax is too large");
		}

		List<Zp.ZpElement> result = new ArrayList<>();
		BigInteger remainder = value.getInteger();

		while (remainder.signum() > 0) {
			BigInteger digit = remainder.mod(BASE);
			remainder = remainder.subtract(digit).divide(BASE);
			result.add(value.getStructure().valueOf(digit));
		}

		if (result.size() > rho)
			throw new RuntimeException("rho too small");

		/*BigInteger b = BigInteger.ONE;
		Zp.ZpElement recreated = value.getStructure().getZeroElement();
		for (Zp.ZpElement r : result) {
			recreated = recreated.add(r.mul(recreated.getStructure().createZnElement(b)));
			b = b.multiply(BASE);
		}
		if (!recreated.equals(value))
			throw new RuntimeException("Bit decomposition doesn't work");*/

		while (result.size() < rho)
			result.add(value.getStructure().getZeroElement());

		return result;
	}

	public StuffThatsSentOverBeforeSpend getStuffSentOver() {
		return stuff;
	}


	public void initProtocol(Zp.ZpElement gamma, Zp.ZpElement eskIsr) {
		//Compute values like in paper
		Group groupG1 = pp.group.getG1();
		Zp zp = new Zp(groupG1.size());
		int rho = rho(zp.size());


		// linking values c0, c1 using the old esk, old dsrndb, and gamma given by the issuer in phase 1
		Zp.ZpElement c0 = usrKeypair.userSecretKey.usk.mul(gamma).add(token.dsrnd0);
		Zp.ZpElement c1 = token.esk.mul(gamma).add(token.dsrnd1);

		//new esk^*
		Zp.ZpElement eskStar = eskusr.add(eskisr);
		List<Zp.ZpElement> esk_i_star = getUaryRepresentationOf(eskStar);

		//Encrypt esk_i_star
		List<Zp.ZpElement> r_i = new ArrayList<>();
		List<GroupElement> w_raised_r_i = new ArrayList<>();
		List<GroupElement> w_raised_r_i_esk_times_bla = new ArrayList<>();
		for (int i=0; i<rho;i++) {
			Zp.ZpElement r = zp.getUniformlyRandomElement();
			r_i.add(r);
			w_raised_r_i.add(pp.w.pow(r));
			w_raised_r_i_esk_times_bla.add(pp.w.pow(r.mul(token.esk).add(esk_i_star.get(i))));
		}


		//Derive other values for the protocol
		GroupElement dsid = pp.w.pow(token.esk);

		//Signatures for vStar = v-k base decomposition
		List<Zp.ZpElement> v_i_star = getUaryRepresentationOf((Zp.ZpElement) token.value.sub(k));
		List<Zp.ZpElement> v_i_star_blinder = new ArrayList<>();
		List<GroupElement> blindedSigmaViStar = new ArrayList<>();
		List<GroupElement> hViStar = new ArrayList<>();
		if (token.value.getInteger().intValue() > Math.pow(SpendInstance.BASE.intValue(), SpendInstance.VMAX_EXPONENT))
			throw new RuntimeException("over the vmax limit");
		for (int i=0;i<SpendInstance.VMAX_EXPONENT;i++) {
			Zp.ZpElement psRnd = zp.getUniformlyRandomUnit();
			v_i_star_blinder.add(zp.getUniformlyRandomElement());
			int digit = v_i_star.get(i).getInteger().intValue();
			blindedSigmaViStar.add(pk.digitsig_sigma_on_i.get(digit).pow(psRnd).op(pp.w.pow(v_i_star_blinder.get(i))));
			hViStar.add(pk.digitsig_h_on_i.get(digit).pow(psRnd));
		}

		//Signatures for eskStar base decomposition
		List<Zp.ZpElement> esk_i_star_blinder = new ArrayList<>();
		List<GroupElement> blindedSigmaEskiStar = new ArrayList<>();
		List<GroupElement> hEskiStar = new ArrayList<>();
		for (int i=0;i<rho;i++) {
			Zp.ZpElement psRnd = zp.getUniformlyRandomUnit();
			esk_i_star_blinder.add(zp.getUniformlyRandomElement());
			int digit = esk_i_star.get(i).getInteger().intValue();
			blindedSigmaEskiStar.add(pk.digitsig_sigma_on_i.get(digit).pow(psRnd).op(pp.w.pow(esk_i_star_blinder.get(i))));
			hEskiStar.add(pk.digitsig_h_on_i.get(digit).pow(psRnd));
		}

		//Blind Cpre for the ^ux proof
		Zp.ZpElement uStar = this.u;
		Zp.ZpElement Cpre0blinder = zp.getUniformlyRandomElement();
		GroupElement Cpre0blinded = ((GroupElementPlainText) cPre.get(0)).get().pow(uStar.inv()).op(pk.h1to6[5].pow(Cpre0blinder)); //TODO store cPre without ^u* instead of undoing that randomization here.
		GroupElement Cpre0powU = ((GroupElementPlainText) cPre.get(0)).get();
		GroupElement Cpre1PowU = ((GroupElementPlainText) cPre.get(1)).get();
		Zp.ZpElement dsrnd0Star = this.dsrnd0; //weird, I know.
		Zp.ZpElement dsrnd1Star = this.dsrnd1; //weird, I know.
		Zp.ZpElement zStar = this.z;
		Zp.ZpElement tStar = this.t;

		stuff = new StuffThatsSentOverBeforeSpend(dsid, w_raised_r_i, w_raised_r_i_esk_times_bla, k, gamma, rho, blindedSigmaViStar, hViStar, blindedSigmaEskiStar, hEskiStar, ((GroupElementPlainText) token.M.get(0)).get(), c0, c1, Cpre0blinded /*Cpre0 * h6^Cpre0blinderVar*/, Cpre0powU, Cpre1PowU, eskIsr);

		this.schnorrProtocol = ZKAKProvider.getSpendDeductSchnorrProverProtocol(pp, pk, dsid, w_raised_r_i, w_raised_r_i_esk_times_bla, k, gamma, rho, blindedSigmaViStar, hViStar, blindedSigmaEskiStar, hEskiStar, ((GroupElementPlainText) token.M.get(0)).get(), c0, c1, Cpre0blinded /*Cpre0 * h6^Cpre0blinderVar*/, Cpre0powU, Cpre1PowU, eskIsr,
				usrKeypair.userSecretKey.usk, token.value, token.z, zStar, token.t, tStar, uStar, token.esk, eskStar, esk_i_star, r_i, esk_i_star_blinder, v_i_star, v_i_star_blinder,  eskusr, token.dsrnd0, dsrnd0Star, token.dsrnd1, dsrnd1Star, Cpre0blinder);
	}

	public Announcement[] generateSchnorrAnnoucements() {
		return schnorrProtocol.generateAnnouncements();
	}

	public Response[] generateSchnorrResponses(Challenge ch) {
		return schnorrProtocol.generateResponses(ch);
	}

}
