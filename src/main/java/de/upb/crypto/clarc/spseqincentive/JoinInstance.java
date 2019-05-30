package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.sig.sps.eq.SPSEQSignature;
import de.upb.crypto.craco.sig.sps.eq.SPSEQSignatureScheme;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

/**
 * A prover instance of the Receive <-> Issue protocol.
 * <p>
 * It is set up with the common input, the prover's private input and the prover instance of the {@link SigmaProtocol}
 * ran during the protocol execution. After setup this instance can be used to generate every message sent from the prover
 * to the verifier. The correct (temporal) order of method invocation is:
 *  1. {@link #initProtocol(Zp.ZpElement)}
 *  2. {@link #generateAnnoucements()}
 *  3. {@link #computeResponses(Challenge)}
 *  4. {@link #join(SPSEQSignature)}
 * After {@link #join(SPSEQSignature)} was run, the prover should have obtained an spseqSignature and a double-spend ID.
 */
public class JoinInstance extends CPreComProofInstance {

	//Zp.ZpElement dsid;
	//PedersenCommitmentValue c;

	public JoinInstance(IncentiveSystemPublicParameters pp, IncentiveProviderPublicKey pk, IncentiveUserKeyPair keyPair, IncentiveUser.CPreComProofValues cPreComProofValues) {
		super(pp, pk, keyPair, cPreComProofValues);
	}

	/** Initializes the ZKAK protocol after receiving the eskisr of the issuer.
	 *
	 * @param eskisr
	 *          issuer's (random) esk share
	 */
	public void initProtocol(Zp.ZpElement eskisr) {
		Group groupG1 = pp.group.getG1();
		Zp zp = new Zp(groupG1.size());

		this.eskisr = eskisr;

		//  use cPre
		open = zp.getUniformlyRandomElement();

		bCom = pk.h1to6[0].pow(usrKeypair.userSecretKey.usk).op(pp.g1.pow(open));

		this.protocol = ZKAKProvider.getIssueReceiveProverProtocol(pp, zp, this);
	}


	/**
	 * Computes the final output of Join.
	 * <p>
	 *
	 * @param spseqSignature
	 *              blinded signature computed by the issuer
	 * @return
	 *      Incentive spseqSignature , ...
	 */
	public TokenDoubleSpendIdPair join(SPSEQSignature spseqSignature) {
		SPSEQSignatureScheme spseqSignatureScheme = new SPSEQSignatureScheme(pk.spseqPublicParameters);

		// compute cPost with eskisr added
		GroupElement cPre0 = ((GroupElementPlainText) cPre.get(0)).get();
		GroupElement cPre1 = ((GroupElementPlainText) cPre.get(1)).get();
		GroupElement cPost0 = cPre0.op(pk.h1to6[1].pow(eskisr.mul(u)));

		Zp.ZpElement eskFinal = eskusr.add(eskisr);

		MessageBlock cPost = new MessageBlock();
		cPost.add(new GroupElementPlainText(cPost0));
		cPost.add(new GroupElementPlainText(cPre1));

		Zp.ZpElement zeroElement = new Zp(pp.group.getG1().size()).getZeroElement();

		boolean b = spseqSignatureScheme.verify(cPost,spseqSignature,pk.spseqVerificationKey);

		// unblind
		SPSEQSignature spseqSignatureFinal = (SPSEQSignature) spseqSignatureScheme.chgRepWithVerify(cPost,spseqSignature,u.inv(),pk.spseqVerificationKey);

		MessageBlock cPostFinal = (MessageBlock) spseqSignatureScheme.chgRepMessage(cPost,u.inv());

		// output spseqSignature
		return new TokenDoubleSpendIdPair(new IncentiveToken(cPostFinal, eskFinal, dsrnd0, dsrnd1, z,t,  zeroElement, spseqSignatureFinal), pp.w.pow(eskFinal));
	}
}
