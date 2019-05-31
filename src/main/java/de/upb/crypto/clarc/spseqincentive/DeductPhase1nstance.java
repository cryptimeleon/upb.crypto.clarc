package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.hashthensign.HashThenSign;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.craco.sig.ps.PSPublicParameters;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.craco.sig.sps.eq.SPSEQSignature;
import de.upb.crypto.craco.sig.sps.eq.SPSEQSignatureScheme;
import de.upb.crypto.math.hash.impl.ByteArrayAccumulator;
import de.upb.crypto.math.hash.impl.VariableOutputLengthHashFunction;
import de.upb.crypto.math.interfaces.hash.HashFunction;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

/**
 *
 */
public class DeductPhase1nstance {

	IncentiveSystemPublicParameters pp;
	IncentiveUserPublicKey userPublicKey;

	IncentiveProviderKeyPair providerKeyPair;

	Zp.ZpElement eskisr;
	MessageBlock cPre;
	Zp.ZpElement tid;
	Zp.ZpElement k;
	Zp.ZpElement gamma;
	GroupElement dsid;

	SigmaProtocol protocol;
	Announcement[] announcements;
	Challenge ch;

	public DeductPhase1nstance(IncentiveSystemPublicParameters pp, IncentiveProviderKeyPair providerKeyPair, IncentiveUserPublicKey userPublicKey, Zp.ZpElement eskisr, Zp.ZpElement gamma, Zp.ZpElement tid, Zp.ZpElement k, GroupElement dsid, MessageBlock cPre) {
		this.pp = pp;
		this.providerKeyPair = providerKeyPair;
		this.userPublicKey = userPublicKey;
		this.eskisr = eskisr;
		this.cPre = cPre;
		this.k = k;
		this.tid = tid;
		this.gamma = gamma;
		this.dsid = dsid;
	}

	/**
	 * Initializes the verfierer protocol of Issue/Receive.
	 *
	 * In particular, this sets up the ZKAK protocol instance, and stores the announcements for the verification in {@link #issue(Response[])}.
	 *
	 * @param cPre
	 *          commitment computed by the receiver that should be signed blindly
	 * @param announcements
	 *          Receiver's announcement
	 */
	public void initProtocol(MessageBlock cPre, GroupElement bCom, Announcement[] announcements) {
		this.protocol = ZKAKProvider.getSpendPhase1VerifierProtocol(pp, new Zp(pp.group.getG1().size()), userPublicKey, providerKeyPair.providerPublicKey, cPre, bCom);
		this.announcements = announcements;
	}

	public Challenge chooseChallenge() {
		this.ch = protocol.chooseChallenge();
		return this.ch;
	}

	public PSSignature endDeductPhase1(Response[] responses) {
		if (this.ch == null) {
			throw new IllegalStateException("Please run the ZKAK to completion first.");
		}
		if(!protocol.verify(announcements, ch, responses)) {
			throw new IllegalStateException("Proof does not accept! Issue aborted...");
		}

		PSExtendedSignatureScheme psScheme = new PSExtendedSignatureScheme(new PSPublicParameters(pp.group.getBilinearMap()));

		HashFunction hashFunction = new VariableOutputLengthHashFunction(psScheme
				.getMaxNumberOfBytesForMapToPlaintext());

		HashThenSign hashThenSign = new HashThenSign(hashFunction,psScheme);

		Group g1 = pp.group.getG1();
		Zp zp = new Zp(g1.size());

		ByteArrayAccumulator byteAccumulator = new ByteArrayAccumulator();
		byteAccumulator.append(tid);
		byteAccumulator.append(dsid);
		byteAccumulator.append(k);
		byteAccumulator.append(cPre);
		byteAccumulator.append(eskisr);
		byteAccumulator.append(gamma);

		PSSignature signature = (PSSignature) hashThenSign.sign(byteAccumulator, providerKeyPair.psSigningKey);

		return signature;
	}



}
