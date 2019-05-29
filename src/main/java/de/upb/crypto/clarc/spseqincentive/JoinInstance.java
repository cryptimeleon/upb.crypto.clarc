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
public class JoinInstance {
	// internal state
	Zp.ZpElement eskusr;
	Zp.ZpElement dsrnd0;
	Zp.ZpElement dsrnd1;
	Zp.ZpElement z;
	Zp.ZpElement t;
	Zp.ZpElement u;
	Zp.ZpElement eskisr;
	MessageBlock cPre;
	GroupElement bCom;
	Zp.ZpElement open;
	// common input
	IncentiveSystemPublicParameters pp;
	IncentiveProviderPublicKey pk;
	IncentiveUserKeyPair usrKeypair;

	//Zp.ZpElement dsid;
	//PedersenCommitmentValue c;

	SigmaProtocol protocol;

	public JoinInstance(IncentiveSystemPublicParameters pp, IncentiveProviderPublicKey pk, IncentiveUserKeyPair keyPair, Zp.ZpElement eskusr, Zp.ZpElement dsrnd0, Zp.ZpElement dsrnd1, Zp.ZpElement z, Zp.ZpElement t, Zp.ZpElement u, MessageBlock cPre) {
		this.pp = pp;
		this.pk = pk;
		this.usrKeypair = keyPair;
		this.eskusr = eskusr;
		this.dsrnd0 = dsrnd0;
		this.dsrnd1 = dsrnd1;
		this.z = z;
		this.t = t;
		this.u = u;
		this.cPre = cPre;
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


		// remove the last group element for the proof
		// value v = 0 => always 1 for every g1
/*		GroupElement[] groupElements = new GroupElement[] {pk.getGroup1ElementsYi()[0],pk.getGroup1ElementsYi()[1], pk.getGroup1ElementsYi()[2]};
		PedersenPublicParameters pedersenPP = new PedersenPublicParameters(pk.getGroup1ElementG(), groupElements, g1);
		PedersenCommitmentScheme pedersen = new PedersenCommitmentScheme(pedersenPP);
		MessageBlock messages = new MessageBlock();
		Stream.of(usrKeypair.userSecretKey.usk, dsid, dsrnd).map(RingElementPlainText::new).collect(Collectors.toCollection(() -> messages));
		PedersenCommitmentPair commitmentPair = pedersen.commit(messages);
		this.c = commitmentPair.getCommitmentValue();
		this.t = commitmentPair.getOpenValue().getRandomValue();*/

		this.protocol = ZKAKProvider.getIssueReceiveProverProtocol(pp, zp, this);
	}

	public MessageBlock getCommitment() {
		return cPre;
	}

	public SigmaProtocol getProtocol() {
		return protocol;
	}

	/**
	 * @return
	 *      announcements of {@link #protocol} sent in the second move of Receive.
	 */
	public Announcement[] generateAnnoucements() {
		return protocol.generateAnnouncements();
	}

	/**
	 *
	 * @param ch
	 *          challenge received by the issuer
	 * @return
	 *          responses sent in the third move of Receive
	 */
	public Response[] computeResponses(Challenge ch) {
		return protocol.generateResponses(ch);
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
		Zp.ZpElement test = eskisr;
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
