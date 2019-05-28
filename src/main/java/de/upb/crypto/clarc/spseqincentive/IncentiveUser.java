package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentScheme;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalCipherText;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalEncryption;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalPlainText;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalPublicKey;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

/**
 * Represents the user of the incentive system,
 * <p>
 * The main task is to set up the prover instances of the protocols ran in the system. We assume that common input was
 * exchanged before hand.
 */
public class IncentiveUser {
	IncentiveSystemPublicParameters pp;
	IncentiveUserKeyPair keyPair;

	public IncentiveUser(IncentiveSystemPublicParameters pp) {
		this.pp = pp;
		IncentiveUserSetup usrSetup = new IncentiveUserSetup();
		this.keyPair = usrSetup.generateUserKeys(this.pp);
	}

	/**
	 * Initializes the {@link JoinInstance} with the common input and computes the first round of Receive.
	 * The first round consists of choosing dsidUsr, and open at random in Zp, and committing to dsidUsr using
	 * ElGamal with randomness open.
	 *
	 * @param pk
	 *          public key of the issuer that signs the incentive token
	 * @return
	 *      the {@link JoinInstance} holding the state of the user during Issue/Receive
	 */
	public JoinInstance initJoin(IncentiveProviderPublicKey pk) {
		Group groupG1 = pp.group.getG1();
		Zp zp = new Zp(groupG1.size());
		//PedersenCommitmentScheme pedersenCommitmentScheme = new PedersenCommitmentScheme(new PedersenPublicParameters(pp.g1,pk.h1to6,groupG1));
		//pedersenCommitmentScheme.commit()

		Zp.ZpElement eskusr = zp.getUniformlyRandomElement();
		Zp.ZpElement dsrnd0 = zp.getUniformlyRandomElement();
		Zp.ZpElement dsrnd1 = zp.getUniformlyRandomElement();
		Zp.ZpElement z = zp.getUniformlyRandomElement();
		Zp.ZpElement t = zp.getUniformlyRandomElement();
		Zp.ZpElement u = zp.getUniformlyRandomElement();

		GroupElement h1Elem = pk.h1to6[0].pow(keyPair.userSecretKey.usk.mul(u));
		GroupElement h2Elem = pk.h1to6[1].pow(eskusr.mul(u));
		GroupElement h3Elem = pk.h1to6[2].pow(dsrnd0.mul(u));
		GroupElement h4Elem = pk.h1to6[3].pow(dsrnd1.mul(u));
		GroupElement h6Elem = pk.h1to6[5].pow(z.mul(u));
		GroupElement h7Elem = pp.h7.pow(t.mul(u));


		// commitment Cpre
		GroupElement cPre0 = h1Elem.op(h2Elem).op(h3Elem).op(h4Elem).op(h6Elem).op(h7Elem);
		GroupElement cPre1 = pp.g1.pow(u);
		MessageBlock cPre = new MessageBlock();
		cPre.add(new GroupElementPlainText(cPre0));
		cPre.add(new GroupElementPlainText(cPre1));

		return new JoinInstance(pp, pk, keyPair, eskusr, dsrnd0, dsrnd1, z, t, u,cPre);
	}

	/**
	 * Initializes the {@link EarnInstance} with the common input and computes the first round of Earn.
	 * The first round consists of randomizing {@code token} as preparation of the ZKAK run in the protocol.
	 *
	 * @param pk
	 *          public key of the issues that signed {@code token}
	 * @param k
	 *          # points the {@code token}'s account is increased
	 * @param token
	 *          token of which the account should be increased
	 *
	 * @return
	 *      the {@link EarnInstance} holding the user's state during the execution of Credit/Earn
	 */
	public EarnInstance initEarn(PSExtendedVerificationKey pk, Zp.ZpElement k, IncentiveToken token) {
		Zp zp = new Zp(pp.group.getG1().size());

		PSSignature signature = token.token;
		GroupElement sigma0 = signature.getGroup1ElementSigma1();
		GroupElement sigma1 = signature.getGroup1ElementSigma2();
		Zp.ZpElement r = zp.getUniformlyRandomUnit();
		Zp.ZpElement rPrime = zp.getUniformlyRandomElement();
		GroupElement sigma0Prime = sigma0.pow(r);
		GroupElement sigma1Prime = (sigma1.op(sigma0.pow(rPrime))).pow(r);
		PSSignature blindedSig = new PSSignature(sigma0Prime, sigma1Prime);


		return new EarnInstance(pp, pk, k, keyPair.userSecretKey, token, rPrime, blindedSig, ZKAKProvider.getCreditEarnProverProtocol(pp, blindedSig, pk, keyPair.userSecretKey.usk, token.dsid, token.dsrnd, token.value, rPrime));
	}

	/**
	 *
	 *
	 * @param pk
	 * @param k
	 * @param dsid
	 * @param token
	 *
	 * @return
	 */
	public SpendInstance initSpend(PSExtendedVerificationKey pk, Zp.ZpElement k, Zp.ZpElement dsid, IncentiveToken token) {
		Group g1 = pp.group.getG1();
		Zp zp = new Zp(g1.size());

		Zp.ZpElement dsidUsrStar = zp.getUniformlyRandomElement();
		Zp.ZpElement openStar = zp.getUniformlyRandomElement();

		// ElGamal commitment
		ElgamalCipherText cUsrStar = elgamalCommit(pp.g1.pow(dsidUsrStar), openStar);

		return new SpendInstance(this.pp, pk, k, dsid, keyPair.userPublicKey.upk, keyPair.userSecretKey.usk, token, dsidUsrStar, openStar, cUsrStar);
	}

	private ElgamalCipherText elgamalCommit(GroupElement message, Zp.ZpElement randomness) {
		Group g1 = pp.group.getG1();
		return (ElgamalCipherText) new ElgamalEncryption(g1).encrypt(new ElgamalPlainText(message), new ElgamalPublicKey(g1, pp.g1, pp.h7), randomness.getInteger());
	}
}
