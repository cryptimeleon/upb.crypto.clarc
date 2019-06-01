package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalCipherText;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalEncryption;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalPlainText;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalPublicKey;
import de.upb.crypto.craco.sig.sps.eq.SPSEQSignature;
import de.upb.crypto.craco.sig.sps.eq.SPSEQSignatureScheme;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.ArrayList;
import java.util.List;

import static de.upb.crypto.clarc.spseqincentive.SpendInstance.getUaryRepresentationOf;
import static de.upb.crypto.clarc.spseqincentive.SpendInstance.rho;

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

	public class CPreComProofValues {
		Zp.ZpElement eskusr;
		Zp.ZpElement dsrnd0;
		Zp.ZpElement dsrnd1;
		Zp.ZpElement z;
		Zp.ZpElement t;
		Zp.ZpElement u;

		GroupElement h1Elem;
		GroupElement h2Elem;
		GroupElement h3Elem;
		GroupElement h4Elem;
		GroupElement h6Elem;
		GroupElement h7Elem;


		// commitment Cpre
		MessageBlock cPre;

		public CPreComProofValues(IncentiveProviderPublicKey pk){
			Group groupG1 = pp.group.getG1();
			Zp zp = new Zp(groupG1.size());

			this.eskusr = zp.getUniformlyRandomElement();
			this.dsrnd0 = zp.getUniformlyRandomElement();
			this.dsrnd1 = zp.getUniformlyRandomElement();
			this.z = zp.getUniformlyRandomElement();
			this.t = zp.getUniformlyRandomElement();
			this.u = zp.getUniformlyRandomElement();

			this.h1Elem = pk.h1to6[0].pow(keyPair.userSecretKey.usk.mul(u));
			this.h2Elem = pk.h1to6[1].pow(eskusr.mul(u));
			this.h3Elem = pk.h1to6[2].pow(dsrnd0.mul(u));
			this.h4Elem = pk.h1to6[3].pow(dsrnd1.mul(u));
			this.h6Elem = pk.h1to6[5].pow(z.mul(u));
			this.h7Elem = pp.h7.pow(t.mul(u));


			// commitment Cpre
			GroupElement cPre0 = h1Elem.op(h2Elem).op(h3Elem).op(h4Elem).op(h6Elem).op(h7Elem);
			GroupElement cPre1 = pp.g1.pow(u);
			this.cPre = new MessageBlock();
			cPre.add(new GroupElementPlainText(cPre0));
			cPre.add(new GroupElementPlainText(cPre1));
		}

	}


	/**
	 * Initializes the {@link JoinInstance} with the common input and computes the first round of Receive.
	 * The first round consists of choosing dsidUsr, and open at random in Zp, and committing to dsidUsr using
	 * ElGamal with randomness open.
	 *
	 * @param pk
	 *          public key of the issuer that signs the incentive spseqSignature
	 * @return
	 *      the {@link JoinInstance} holding the state of the user during Issue/Receive
	 */
	public JoinInstance initJoin(IncentiveProviderPublicKey pk) {

		//PedersenCommitmentScheme pedersenCommitmentScheme = new PedersenCommitmentScheme(new PedersenPublicParameters(pp.g1,pk.h1to6,groupG1));
		//pedersenCommitmentScheme.commit()


		return new JoinInstance(pp, pk, keyPair, new CPreComProofValues(pk));
	}

	/**
	 * Initializes the {@link EarnInstance} with the common input and computes the first round of Earn.
	 * The first round consists of randomizing {@code spseqSignature} as preparation of the ZKAK run in the protocol.
	 *
	 * @param pk
	 *          public key of the issues that signed {@code spseqSignature}
	 * @param k
	 *          # points the {@code spseqSignature}'s account is increased
	 * @param token
	 *          spseqSignature of which the account should be increased
	 *
	 * @return
	 *      the {@link EarnInstance} holding the user's state during the execution of Credit/Earn
	 */
	public EarnInstance initEarn(IncentiveProviderPublicKey pk, Zp.ZpElement k, IncentiveToken token) {
		Zp zp = new Zp(pp.group.getG1().size());

		// use sps-eq signature scheme to change the representative and to randomize the signature before
		// sending it to the issuer

		SPSEQSignatureScheme spseqSignatureScheme = new SPSEQSignatureScheme(pk.spseqPublicParameters);

		Zp.ZpElement s = zp.getUniformlyRandomUnit();

		SPSEQSignature spseqSignatureR = (SPSEQSignature) spseqSignatureScheme.chgRepWithVerify(token.M,token.spseqSignature,s,pk.spseqVerificationKey);

		MessageBlock cTupleR = (MessageBlock) spseqSignatureScheme.chgRepMessage(token.M,s);

		return new EarnInstance(pp, pk, k, keyPair.userSecretKey, token, s, spseqSignatureR, cTupleR, ZKAKProvider.getCreditEarnProverProtocol(pp, spseqSignatureR, pk, keyPair.userSecretKey.usk, token, s));
	}

	/**
	 *
	 *
	 * @param pk
	 *
	 * @return
	 */
	public SpendPhase1Instance initSpendPhase1(IncentiveProviderPublicKey pk, Zp.ZpElement k, IncentiveToken token) {

		return new SpendPhase1Instance(pp, pk, keyPair, k, token, new CPreComProofValues(pk));
	}


	public SpendInstance initSpendPhase2(IncentiveProviderPublicKey pk, Zp.ZpElement k, CPreComProofValues cPreComProofValues, IncentiveToken token, Zp.ZpElement gamma, Zp.ZpElement eskisr){
		SpendInstance instance = new SpendInstance(pp, pk, keyPair, k, token, cPreComProofValues);
		instance.initProtocol(gamma, eskisr);
		return instance;
	}

	private ElgamalCipherText elgamalCommit(GroupElement message, Zp.ZpElement randomness) {
		Group g1 = pp.group.getG1();
		return (ElgamalCipherText) new ElgamalEncryption(g1).encrypt(new ElgamalPlainText(message), new ElgamalPublicKey(g1, pp.g1, pp.h7), randomness.getInteger());
	}
}
