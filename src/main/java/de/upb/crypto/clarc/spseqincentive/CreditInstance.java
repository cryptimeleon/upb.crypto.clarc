package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.craco.sig.ps.PSSigningKey;
import de.upb.crypto.craco.sig.sps.eq.SPSEQPublicParameters;
import de.upb.crypto.craco.sig.sps.eq.SPSEQSignature;
import de.upb.crypto.craco.sig.sps.eq.SPSEQSignatureScheme;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

/**
 * A verifier instance of the Earn <-> Credit protocol.
 * <p>
 * It is set up with the common input, the verifier's private input, the verifier instance of the {@link SigmaProtocol}
 * ran during the protocol execution and the annoucement sent by the prover as the first message. After setup this instance
 * can be used to generate every message sent from the verifier to the prover.
 * The correct (temporal) order of method invocation is:
 *  1. {@link #chooseChallenge()}
 *  2. {@link #credit(Response[])}
 */
public class CreditInstance {
	IncentiveSystemPublicParameters pp;
	IncentiveProviderPublicKey pk;
	IncentiveProviderSecretKey sk;
	Zp.ZpElement k;
	MessageBlock cPre;

	SPSEQSignature spseqSignature;
	SigmaProtocol protocol;
	Announcement[] announcements;
	Challenge ch;

	// TODO: ZKPoK fromm issuer to user for the secret key is missing

	public CreditInstance(IncentiveSystemPublicParameters pp, IncentiveProviderPublicKey pk, IncentiveProviderSecretKey sk, Zp.ZpElement k, MessageBlock cPre, SPSEQSignature spseqSignature, SigmaProtocol protocol, Announcement[] announcements) {
		this.pp = pp;
		this.pk = pk;
		this.sk = sk;
		this.k = k;
		this.cPre = cPre;
		this.spseqSignature = spseqSignature;
		this.protocol = protocol;
		this.announcements = announcements;
	}

	public Challenge chooseChallenge() {
		this.ch = protocol.chooseChallenge();
		return this.ch;
	}

	/**
	 * Updates the randomized spseqSignature by {@link #k} points.
	 *
	 * @param responses
	 *          responses of the ZKAK protocol
	 * @return
	 *      updated spseqSignature
	 */
	public SPSEQSignature credit(Response[] responses) {
		SPSEQSignatureScheme spseqSignatureScheme = new SPSEQSignatureScheme(pk.spseqPublicParameters);

		if(!spseqSignatureScheme.verify(cPre,spseqSignature,pk.spseqVerificationKey)) {
			throw new IllegalStateException("Given signature not valid, will not isse new signature on new point value");
		}


		// generate signature
		GroupElement cPre0 = ((GroupElementPlainText) cPre.get(0)).get();
		GroupElement cPre1 = ((GroupElementPlainText) cPre.get(1)).get();
		GroupElement cPost0 = cPre0.asPowProductExpression().op(cPre1,(sk.q[4].mul(k))).evaluate();

		MessageBlock cPost = new MessageBlock();
		cPost.add(new GroupElementPlainText(cPost0));
		cPost.add(new GroupElementPlainText(cPre1));

		SPSEQSignature signature = (SPSEQSignature) spseqSignatureScheme.sign(cPost, sk.spseqSigningKey);
		return signature;
	}
}
