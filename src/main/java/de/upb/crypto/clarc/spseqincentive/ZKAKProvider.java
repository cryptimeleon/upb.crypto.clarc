package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof.ZeroToUPowLRangeProofProtocol;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof.ZeroToUPowLRangeProofProtocolFactory;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof.ZeroToUPowLRangeProofPublicParameters;
import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.expressions.arith.*;
import de.upb.crypto.clarc.protocols.expressions.comparison.ArithComparisonExpression;
import de.upb.crypto.clarc.protocols.expressions.comparison.GroupElementEqualityExpression;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.protocolfactory.GeneralizedSchnorrProtocolFactory;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentPair;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalCipherText;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.craco.sig.sps.eq.SPSEQSignature;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.mappings.PairingProductExpression;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.interfaces.structures.PowProductExpression;
import de.upb.crypto.math.interfaces.structures.RingAdditiveGroup;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

public class ZKAKProvider {

	/* Defines the factory for the ZKAK ran in the Issue/Receive protocol */
	private static GeneralizedSchnorrProtocolFactory getIssueJoinProtocolFactory(IncentiveSystemPublicParameters pp, Zp zp, IncentiveUserPublicKey userPublicKey, IncentiveProviderPublicKey pk, MessageBlock cPre, GroupElement bCom) {

		ZnVariable uskVar = new ZnVariable("usk");
		ZnVariable uskuVar = new ZnVariable("usku");
		ZnVariable eskusrVar = new ZnVariable("eskusr");
		ZnVariable dsrnd0Var = new ZnVariable("dsrnd0");
		ZnVariable dsrnd1Var = new ZnVariable("dsrnd1");
		ZnVariable zVar = new ZnVariable("z");
		ZnVariable tVar = new ZnVariable("t");
		ZnVariable uVar = new ZnVariable("u");
		ZnVariable uInvVar = new ZnVariable("uinv");
		ZnVariable openVar = new ZnVariable("open");
		ZnVariable openUVar = new ZnVariable("openu");


		// problem 1: Cpre =
		ArithGroupElementExpression h1Expr = new NumberGroupElementLiteral(pk.h1to6[0]);
		ArithGroupElementExpression h2Expr = new NumberGroupElementLiteral(pk.h1to6[1]);
		ArithGroupElementExpression h3Expr = new NumberGroupElementLiteral(pk.h1to6[2]);
		ArithGroupElementExpression h4Expr = new NumberGroupElementLiteral(pk.h1to6[3]);
		ArithGroupElementExpression h6Expr = new NumberGroupElementLiteral(pk.h1to6[5]);
		ArithGroupElementExpression h7Expr = new NumberGroupElementLiteral(pp.h7);

		ArithGroupElementExpression h1UskUExpr = new PowerGroupElementExpression(h1Expr, uskuVar);
		ArithGroupElementExpression h2EskusrExpr = new PowerGroupElementExpression(h2Expr, eskusrVar);
		ArithGroupElementExpression h3Dsrnd0Expr = new PowerGroupElementExpression(h3Expr, dsrnd0Var);
		ArithGroupElementExpression h4Dsrnd1Expr = new PowerGroupElementExpression(h4Expr, dsrnd1Var);
		ArithGroupElementExpression h6ZExpr = new PowerGroupElementExpression(h6Expr, zVar);
		ArithGroupElementExpression h7TExpr = new PowerGroupElementExpression(h7Expr, tVar);

		NumberGroupElementLiteral cPre0 = new NumberGroupElementLiteral(((GroupElementPlainText)cPre.get(0)).get());

		ArithGroupElementExpression rhsExpr = new ProductGroupElementExpression(h1UskUExpr, h2EskusrExpr,h3Dsrnd0Expr,h4Dsrnd1Expr,h6ZExpr,h7TExpr);
		GroupElementEqualityExpression problem1 = new GroupElementEqualityExpression(cPre0, rhsExpr);

		// problem 2: upk = w^{usk}
		ArithGroupElementExpression upkExpr = new NumberGroupElementLiteral(userPublicKey.upk);
		NumberGroupElementLiteral wExpr = new NumberGroupElementLiteral(pp.w);
		PowerGroupElementExpression wUskExpr = new PowerGroupElementExpression(wExpr, uskVar);

		GroupElementEqualityExpression problem2 = new GroupElementEqualityExpression(upkExpr, new ProductGroupElementExpression(wUskExpr));

		// problem 1b: g1^u
		NumberGroupElementLiteral cPre1 = new NumberGroupElementLiteral(((GroupElementPlainText)cPre.get(1)).get());
		ArithGroupElementExpression g1Expr = new NumberGroupElementLiteral(pp.g1);

		PowerGroupElementExpression g1UExpr = new PowerGroupElementExpression(g1Expr, uVar);
		GroupElementEqualityExpression problem1b = new GroupElementEqualityExpression(cPre1, new ProductGroupElementExpression(g1UExpr));


		// problem 3: bCom = h1^usk * g1^open
		NumberGroupElementLiteral bComLit = new NumberGroupElementLiteral(bCom);
		ArithGroupElementExpression h1UskExpr = new PowerGroupElementExpression(h1Expr, uskVar);
		ArithGroupElementExpression g1OpenExpr = new PowerGroupElementExpression(g1Expr, openVar);
		ArithGroupElementExpression rhsBComExpr = new ProductGroupElementExpression(h1UskExpr,g1OpenExpr);
		GroupElementEqualityExpression problem3 = new GroupElementEqualityExpression(bComLit, rhsBComExpr);


		// problem 4: bCom^u = h1^{usk*u} * g1^{open*u}
		NumberGroupElementLiteral neutralLit = new NumberGroupElementLiteral(pp.group.getG1().getNeutralElement());
		NumberGroupElementLiteral bComInvLit = new NumberGroupElementLiteral(bCom.inv());
		PowerGroupElementExpression bComUExpr = new PowerGroupElementExpression(bComInvLit, uVar);
		ArithGroupElementExpression g1OpenUExpr = new PowerGroupElementExpression(g1Expr, openUVar);
		ArithGroupElementExpression rhsBComUExpr = new ProductGroupElementExpression(h1UskUExpr,g1OpenUExpr,bComUExpr);
		GroupElementEqualityExpression problem4 = new GroupElementEqualityExpression(neutralLit, rhsBComUExpr);


		return new GeneralizedSchnorrProtocolFactory(new GroupElementEqualityExpression[]{problem1, problem1b, problem2, problem3, problem4}, zp);
	}

	private static GeneralizedSchnorrProtocolFactory getSpendPhase1ProtocolFactory(IncentiveSystemPublicParameters pp, Zp zp, IncentiveUserPublicKey userPublicKey, IncentiveProviderPublicKey pk, MessageBlock cPre, GroupElement bCom) {
		ZnVariable uskVar = new ZnVariable("usk");
		ZnVariable uskuVar = new ZnVariable("usku");
		ZnVariable eskusrVar = new ZnVariable("eskusr");
		ZnVariable dsrnd0Var = new ZnVariable("dsrnd0");
		ZnVariable dsrnd1Var = new ZnVariable("dsrnd1");
		ZnVariable zVar = new ZnVariable("z");
		ZnVariable tVar = new ZnVariable("t");
		ZnVariable uVar = new ZnVariable("u");
		ZnVariable uInvVar = new ZnVariable("uinv");
		ZnVariable openVar = new ZnVariable("open");
		ZnVariable openUVar = new ZnVariable("openu");


		// problem 1: Cpre =
		ArithGroupElementExpression h1Expr = new NumberGroupElementLiteral(pk.h1to6[0]);
		ArithGroupElementExpression h2Expr = new NumberGroupElementLiteral(pk.h1to6[1]);
		ArithGroupElementExpression h3Expr = new NumberGroupElementLiteral(pk.h1to6[2]);
		ArithGroupElementExpression h4Expr = new NumberGroupElementLiteral(pk.h1to6[3]);
		ArithGroupElementExpression h6Expr = new NumberGroupElementLiteral(pk.h1to6[5]);
		ArithGroupElementExpression h7Expr = new NumberGroupElementLiteral(pp.h7);

		ArithGroupElementExpression h1UskUExpr = new PowerGroupElementExpression(h1Expr, uskuVar);
		ArithGroupElementExpression h2EskusrExpr = new PowerGroupElementExpression(h2Expr, eskusrVar);
		ArithGroupElementExpression h3Dsrnd0Expr = new PowerGroupElementExpression(h3Expr, dsrnd0Var);
		ArithGroupElementExpression h4Dsrnd1Expr = new PowerGroupElementExpression(h4Expr, dsrnd1Var);
		ArithGroupElementExpression h6ZExpr = new PowerGroupElementExpression(h6Expr, zVar);
		ArithGroupElementExpression h7TExpr = new PowerGroupElementExpression(h7Expr, tVar);

		NumberGroupElementLiteral cPre0 = new NumberGroupElementLiteral(((GroupElementPlainText)cPre.get(0)).get());

		ArithGroupElementExpression rhsExpr = new ProductGroupElementExpression(h1UskUExpr, h2EskusrExpr,h3Dsrnd0Expr,h4Dsrnd1Expr,h6ZExpr,h7TExpr);
		GroupElementEqualityExpression problem1 = new GroupElementEqualityExpression(cPre0, rhsExpr);


		// problem 1b: g1^u
		NumberGroupElementLiteral cPre1 = new NumberGroupElementLiteral(((GroupElementPlainText)cPre.get(1)).get());
		ArithGroupElementExpression g1Expr = new NumberGroupElementLiteral(pp.g1);

		PowerGroupElementExpression g1UExpr = new PowerGroupElementExpression(g1Expr, uVar);
		GroupElementEqualityExpression problem1b = new GroupElementEqualityExpression(cPre1, new ProductGroupElementExpression(g1UExpr));


		// problem 3: bCom = h1^usk * g1^open
		NumberGroupElementLiteral bComLit = new NumberGroupElementLiteral(bCom);
		ArithGroupElementExpression h1UskExpr = new PowerGroupElementExpression(h1Expr, uskVar);
		ArithGroupElementExpression g1OpenExpr = new PowerGroupElementExpression(g1Expr, openVar);
		ArithGroupElementExpression rhsBComExpr = new ProductGroupElementExpression(h1UskExpr,g1OpenExpr);
		GroupElementEqualityExpression problem3 = new GroupElementEqualityExpression(bComLit, rhsBComExpr);


		// problem 4: bCom^u = h1^{usk*u} * g1^{open*u}
		NumberGroupElementLiteral neutralLit = new NumberGroupElementLiteral(pp.group.getG1().getNeutralElement());
		NumberGroupElementLiteral bComInvLit = new NumberGroupElementLiteral(bCom.inv());
		PowerGroupElementExpression bComUExpr = new PowerGroupElementExpression(bComInvLit, uVar);
		ArithGroupElementExpression g1OpenUExpr = new PowerGroupElementExpression(g1Expr, openUVar);
		ArithGroupElementExpression rhsBComUExpr = new ProductGroupElementExpression(h1UskUExpr,g1OpenUExpr,bComUExpr);
		GroupElementEqualityExpression problem4 = new GroupElementEqualityExpression(neutralLit, rhsBComUExpr);


		return new GeneralizedSchnorrProtocolFactory(new GroupElementEqualityExpression[]{problem1, problem1b, problem3, problem4}, zp);
	}


	/* Returns the prover protocol of the ZKAK ran in Issue/Receive */
	static SigmaProtocol getIssueReceiveProverProtocol(IncentiveSystemPublicParameters pp, Zp zp, CPreComProofInstance joinInstance) {

		HashMap<String, Zp.ZpElement> witnessMapping = new HashMap<>();
		witnessMapping.put("usk", joinInstance.usrKeypair.userSecretKey.usk);
		witnessMapping.put("usku", joinInstance.usrKeypair.userSecretKey.usk.mul(joinInstance.u));
		witnessMapping.put("eskusr", joinInstance.eskusr.mul(joinInstance.u));
		witnessMapping.put("dsrnd0", joinInstance.dsrnd0.mul(joinInstance.u));
		witnessMapping.put("dsrnd1", joinInstance.dsrnd1.mul(joinInstance.u));
		witnessMapping.put("z", joinInstance.z.mul(joinInstance.u));
		witnessMapping.put("t", joinInstance.t.mul(joinInstance.u));
		witnessMapping.put("u", joinInstance.u);
		witnessMapping.put("uinv", joinInstance.u.inv());
		witnessMapping.put("open", joinInstance.open);
		witnessMapping.put("openu", joinInstance.open.mul(joinInstance.u));


		return getIssueJoinProtocolFactory(pp, zp, joinInstance.usrKeypair.userPublicKey, joinInstance.pk, joinInstance.cPre, joinInstance.bCom).createProverGeneralizedSchnorrProtocol(witnessMapping);
	}


	public static SigmaProtocol getSpendPhase1ProverProtocol(IncentiveSystemPublicParameters pp, Zp zp, SpendPhase1Instance spendPhase1Instance) {
		HashMap<String, Zp.ZpElement> witnessMapping = new HashMap<>();
		witnessMapping.put("usk", spendPhase1Instance.usrKeypair.userSecretKey.usk);
		witnessMapping.put("usku", spendPhase1Instance.usrKeypair.userSecretKey.usk.mul(spendPhase1Instance.u));
		witnessMapping.put("eskusr", spendPhase1Instance.eskusr.mul(spendPhase1Instance.u));
		witnessMapping.put("dsrnd0", spendPhase1Instance.dsrnd0.mul(spendPhase1Instance.u));
		witnessMapping.put("dsrnd1", spendPhase1Instance.dsrnd1.mul(spendPhase1Instance.u));
		witnessMapping.put("z", spendPhase1Instance.z.mul(spendPhase1Instance.u));
		witnessMapping.put("t", spendPhase1Instance.t.mul(spendPhase1Instance.u));
		witnessMapping.put("u", spendPhase1Instance.u);
		witnessMapping.put("uinv", spendPhase1Instance.u.inv());
		witnessMapping.put("open", spendPhase1Instance.open);
		witnessMapping.put("openu", spendPhase1Instance.open.mul(spendPhase1Instance.u));


		return getSpendPhase1ProtocolFactory(pp, zp, spendPhase1Instance.usrKeypair.userPublicKey, spendPhase1Instance.pk, spendPhase1Instance.cPre, spendPhase1Instance.bCom).createProverGeneralizedSchnorrProtocol(witnessMapping);

	}


	static SigmaProtocol getSpendPhase1VerifierProtocol(IncentiveSystemPublicParameters pp, Zp zp, IncentiveUserPublicKey userPublicKey, IncentiveProviderPublicKey providerPublicKey, MessageBlock cPre, GroupElement bCom) {
		return getSpendPhase1ProtocolFactory(pp, zp, userPublicKey, providerPublicKey, cPre, bCom).createVerifierGeneralizedSchnorrProtocol();
	}

	static SigmaProtocol getIssueJoinVerifierProtocol(IncentiveSystemPublicParameters pp, Zp zp, IncentiveUserPublicKey userPublicKey, IncentiveProviderPublicKey providerPublicKey, MessageBlock cPre, GroupElement bCom) {
		return getIssueJoinProtocolFactory(pp, zp, userPublicKey, providerPublicKey, cPre, bCom).createVerifierGeneralizedSchnorrProtocol();
	}

	private static GeneralizedSchnorrProtocolFactory getPSVerifyProtocolFactory(IncentiveSystemPublicParameters pp, SPSEQSignature spseqSignature, IncentiveProviderPublicKey pk) {
		//GroupElementEqualityExpression problem = getPSVerifyProtocolProblem(pp, spseqSignature, pk);
		return null;
	}
	/*
	private static GroupElementEqualityExpression getPSVerifyProtocolProblem(IncentiveSystemPublicParameters pp, PSSignature randtoken, PSExtendedVerificationKey pk) {
		ZnVariable uskVar = new ZnVariable("usk");
		ZnVariable dsidVar = new ZnVariable("dsid");
		ZnVariable dsrndVar = new ZnVariable("dsrnd");
		ZnVariable vVar = new ZnVariable("v");
		ZnVariable rPrimeVar = new ZnVariable("rPrime");

		BilinearMap e = pp.group.getBilinearMap();

		GroupElement sigma0 = randtoken.getGroup1ElementSigma1();
		GroupElement sigma1 = randtoken.getGroup1ElementSigma2();

		GroupElement tildeX = pk.getGroup2ElementTildeX();
		GroupElement tildeG = pk.getGroup2ElementTildeG();
		GroupElement lhs = (e.apply(sigma0, tildeX).inv()).op(e.apply(sigma1, tildeG));
		ArithGroupElementExpression lhsExpr = new NumberGroupElementLiteral(lhs);

		ArithGroupElementExpression sigma0Expr = new NumberGroupElementLiteral(sigma0);
		ArithGroupElementExpression tildeGExpr = new NumberGroupElementLiteral(tildeG);
		ArithGroupElementExpression tildeY1Expr = new NumberGroupElementLiteral(pk.getGroup2ElementsTildeYi()[0]);
		ArithGroupElementExpression tildeY2Expr = new NumberGroupElementLiteral(pk.getGroup2ElementsTildeYi()[1]);
		ArithGroupElementExpression tildeY3Expr = new NumberGroupElementLiteral(pk.getGroup2ElementsTildeYi()[2]);
		ArithGroupElementExpression tildeY4Expr = new NumberGroupElementLiteral(pk.getGroup2ElementsTildeYi()[3]);

		List<ArithGroupElementExpression> factorsRHS = Arrays.asList(
				// e( sigma0, g1~)^r'
				new PowerGroupElementExpression(new PairingGroupElementExpression(e, sigma0Expr, tildeGExpr), rPrimeVar),
				// e(sigma0, Y1~)^usk
				new PowerGroupElementExpression(new PairingGroupElementExpression(e, sigma0Expr, tildeY1Expr), uskVar),
				// e(sigma0, Y2~)^dsidInGroup
				new PowerGroupElementExpression(new PairingGroupElementExpression(e, sigma0Expr, tildeY2Expr), dsidVar),
				// e(sigma0, Y3~)^dsrnd
				new PowerGroupElementExpression(new PairingGroupElementExpression(e, sigma0Expr, tildeY3Expr), dsrndVar),
				// e(sigma0, Y4~)^v
				new PowerGroupElementExpression(new PairingGroupElementExpression(e, sigma0Expr, tildeY4Expr), vVar)
		);

		return new GroupElementEqualityExpression(lhsExpr, new ProductGroupElementExpression(factorsRHS));
	}
	*/

	static GeneralizedSchnorrProtocol getCreditEarnProverProtocol(IncentiveSystemPublicParameters pp, SPSEQSignature spseqSignatureR, IncentiveProviderPublicKey pk, Zp.ZpElement usk, IncentiveToken token, Zp.ZpElement s) {
		/*HashMap<String, Zp.ZpElement> witnessMapping = new HashMap<>();
		witnessMapping.put("usk", usk);
		witnessMapping.put("eskusr", token.esk);
		witnessMapping.put("dsrnd0", token.dsrnd0);
		witnessMapping.put("dsrnd1", token.dsrnd1);
		witnessMapping.put("z", token.z);
		witnessMapping.put("t", token.t);
		witnessMapping.put("s", s);*/

		return null;
	}

	static GeneralizedSchnorrProtocol getCreditEarnVerifierProtocol(IncentiveSystemPublicParameters pp, SPSEQSignature spseqSignature, IncentiveProviderPublicKey pk) {
		return getPSVerifyProtocolFactory(pp, spseqSignature, pk).createVerifierGeneralizedSchnorrProtocol();
	}

	public static ArithGroupElementExpression powExpr(GroupElement g, ZnVariable x) {
		return new PowerGroupElementExpression(new NumberGroupElementLiteral(g), x);
	}

	public static ArithGroupElementExpression prodExpr(ArithGroupElementExpression... exprs) {
		return new ProductGroupElementExpression(exprs);
	}

	public static GroupElementEqualityExpression equalExpr(GroupElement lhs, ArithGroupElementExpression rhs) {
		if (rhs instanceof PowerGroupElementExpression) {
			rhs = prodExpr(rhs);
		}
		return new GroupElementEqualityExpression(new NumberGroupElementLiteral(lhs), rhs);
	}

	public static GroupElementEqualityExpression equalExpr(ArithGroupElementExpression lhs, ArithGroupElementExpression rhs) {
		if (rhs instanceof PowerGroupElementExpression) {
			rhs = prodExpr(rhs);
		}
		return new GroupElementEqualityExpression(lhs, rhs);
	}

	public static ArithGroupElementExpression pairExpr(BilinearMap map, ArithGroupElementExpression lhs, ArithGroupElementExpression rhs, ZnVariable x) {
		return new PowerGroupElementExpression(new PairingGroupElementExpression(map, lhs, rhs), x);
	}

	public static ArithGroupElementExpression pairExpr(BilinearMap map, GroupElement lhs, GroupElement rhs, ZnVariable x) {
		return new PowerGroupElementExpression(new PairingGroupElementExpression(map, new NumberGroupElementLiteral(lhs), new NumberGroupElementLiteral(rhs)), x);
	}

	public static ArithGroupElementExpression pairExpr(BilinearMap map, GroupElement lhs, GroupElement rhs) {
		return new PairingGroupElementExpression(map, new NumberGroupElementLiteral(lhs), new NumberGroupElementLiteral(rhs));
	}

	private static GeneralizedSchnorrProtocolFactory getSpendDeductSchnoorProtocolFactory(IncentiveSystemPublicParameters pp, IncentiveProviderPublicKey providerPublicKey, GroupElement dsid, List<GroupElement> ctraceRandomness, List<GroupElement> ctraceCiphertexts, Zp.ZpElement k, Zp.ZpElement gamma, int rho, List<GroupElement> blindedSigmaViStar, List<GroupElement> hViStar, List<GroupElement> blindedSigmaEskiStar, List<GroupElement> hEskiStar, GroupElement commitmentC0, Zp.ZpElement c0, Zp.ZpElement c1, GroupElement Cpre0blinded /*Cpre0 * h6^Cpre0blinderVar*/, GroupElement Cpre0powU, GroupElement Cpre1PowU, Zp.ZpElement eskIsr) {
		Zp zp = new Zp(pp.group.getG1().size());
		RingAdditiveGroup.RingAdditiveGroupElement oneInZp = zp.getOneElement().toAdditiveGroupElement(); //generator of additive Zp
		List<RingAdditiveGroup.RingAdditiveGroupElement> base_to_the_i = new ArrayList<>();
		for (int i=0;i<rho;i++)
			base_to_the_i.add(zp.valueOf(SpendInstance.BASE.pow(i)).toAdditiveGroupElement());

		ZnVariable uskVar = new ZnVariable("usk");
		ZnVariable vVar = new ZnVariable("v");
		ZnVariable zVar = new ZnVariable("z");
		ZnVariable zStarVar = new ZnVariable("zStar");
		ZnVariable tVar = new ZnVariable("t");
		ZnVariable tStarVar = new ZnVariable("tStar");
		ZnVariable uStarVar = new ZnVariable("uStar");
		ZnVariable eskVar = new ZnVariable("esk");
		ZnVariable eskStarVar = new ZnVariable("eskStar");
		List<ZnVariable> esk_i_starVar = new ArrayList<>();
		List<ZnVariable> esk_iStarBlindersVar = new ArrayList<>();
		List<ZnVariable> r_iVar = new ArrayList<>();
		for (int i=0;i<rho;i++) {
			esk_i_starVar.add(new ZnVariable("esk_" + i + "_star")); //base-decomp of esk*
			r_iVar.add(new ZnVariable("r_" + i));
			esk_iStarBlindersVar.add(new ZnVariable("esk_"+i+"_star_blinder"));
		}

		List<ZnVariable> v_iStarVar = new ArrayList<>(); //base decomposition of v* = v-k
		List<ZnVariable> v_iStarBlindersVar = new ArrayList<>(); //values used to blind the signatures for digits of v_iStar with, i.e. sigma' = \sigma * w^v_iStarBLinder
		for (int i=0; i<SpendInstance.VMAX_EXPONENT; i++) {
			v_iStarVar.add(new ZnVariable("v_"+i+"_star"));
			v_iStarBlindersVar.add(new ZnVariable("v_"+i+"_star_blinder"));
		}
		ZnVariable eskusrStarVar = new ZnVariable("eskusrStar");
		ZnVariable dsrnd0Var = new ZnVariable("dsrnd0");
		ZnVariable dsrnd0StarVar = new ZnVariable("dsrnd0Star");
		ZnVariable dsrnd1Var = new ZnVariable("dsrnd1");
		ZnVariable dsrnd1StarVar = new ZnVariable("dsrnd1Star");

		//For the double-exponent opening
		ZnVariable Cpre0blinderVar = new ZnVariable("Cpre0blinder"); //Cpre0 * h6^Cpre0blinderVar
		ZnVariable Cpre0blinderTimesUStarVar = new ZnVariable("Cpre0blinderTimesUStar"); //Cpre0blinderVar*uStarVar


		//ZnVariable uskuVar = new ZnVariable("usku");
		//ZnVariable uInvVar = new ZnVariable("uinv");
		//ZnVariable openVar = new ZnVariable("open");
		//ZnVariable openUVar = new ZnVariable("openu");

		List<GroupElementEqualityExpression> problems = new ArrayList<>();

		// c0 = usk * gamma + dsrnd0
		problems.add(equalExpr(oneInZp.pow(c0), prodExpr(powExpr(oneInZp.pow(gamma), uskVar), powExpr(oneInZp, dsrnd0Var))));

		// c1 = esk * gamma + dsrnd1
		problems.add(equalExpr(oneInZp.pow(c1), prodExpr(powExpr(oneInZp.pow(gamma), eskVar), powExpr(oneInZp, dsrnd1Var))));

		//dsid = w^esk
		problems.add(equalExpr(dsid, powExpr(pp.w, eskVar)));

		//open C
		problems.add(equalExpr(commitmentC0, prodExpr(
			powExpr(providerPublicKey.h1to6[0], uskVar),
			powExpr(providerPublicKey.h1to6[1], eskVar),
			powExpr(providerPublicKey.h1to6[2], dsrnd0Var),
			powExpr(providerPublicKey.h1to6[3], dsrnd1Var),
			powExpr(providerPublicKey.h1to6[4], vVar),
			powExpr(providerPublicKey.h1to6[5], zVar),
			powExpr(pp.h7, tVar)
		)));

		// open Cpre
		//    open Cpre0blinded = Cpre0 * h6^Cpre0blinder
		problems.add(
				equalExpr(Cpre0blinded.op(providerPublicKey.h1to6[4].pow(k).inv()), //account for -k term on rhs in paper
						prodExpr(
								powExpr(providerPublicKey.h1to6[0], uskVar),
								powExpr(providerPublicKey.h1to6[1], eskusrStarVar),
								powExpr(providerPublicKey.h1to6[2], dsrnd0StarVar),
								powExpr(providerPublicKey.h1to6[3], dsrnd1StarVar),
								powExpr(providerPublicKey.h1to6[4], vVar),
								powExpr(providerPublicKey.h1to6[5], zStarVar),
								powExpr(pp.h7, tStarVar),
								powExpr(providerPublicKey.h1to6[5], Cpre0blinderVar)
						)
				)
		);

		//    Cpre0powU = Cpre0blinded^u * h6^Cpre0blinderPowU //now extractor has opening open(Cpre0)^u for Cpre0powU, but with h6^(Cpre0blinder*u-Cpre0blinderPowU)
		problems.add(equalExpr(Cpre0powU, prodExpr(powExpr(Cpre0blinded, uStarVar), powExpr(providerPublicKey.h1to6[5], Cpre0blinderTimesUStarVar))));

		//    Cpre1powU
		problems.add(equalExpr(Cpre1PowU, powExpr(pp.g1, uStarVar)));

		// esk^* = eskusr* + eskisr*
		problems.add(equalExpr(oneInZp.pow(eskIsr), prodExpr(
				powExpr(oneInZp.inv(), eskusrStarVar),
				powExpr(oneInZp, eskStarVar)
		)));

		// v >= k
		//    v* = v-k base decomp: -k = \sum v_i^* base^i -v with only few summands (VMAX_EXPONENT)
		List<ArithGroupElementExpression> exprs = new ArrayList<>();
		for (int i=0;i<SpendInstance.VMAX_EXPONENT;i++)
			exprs.add(powExpr(base_to_the_i.get(i), v_iStarVar.get(i)));
		exprs.add(powExpr(oneInZp.inv(), vVar));
		problems.add(equalExpr(zp.valueOf(k.getInteger()).neg().toAdditiveGroupElement(), prodExpr(exprs.stream().toArray(ArithGroupElementExpression[]::new))));

		//    v_i* < base: check blinded signature: e(sigma_blind, g2) * e(h, public_x)^-1 = e(h, public_y)^m * e(w, g2)^unblinder
		for (int i=0; i<SpendInstance.VMAX_EXPONENT;i++) {
			problems.add(equalExpr(
					prodExpr(
							pairExpr(pp.group.getBilinearMap(), blindedSigmaViStar.get(i), providerPublicKey.digitsig_g2),
							pairExpr(pp.group.getBilinearMap(), hViStar.get(i).inv(), providerPublicKey.digitsig_public_x)
					), prodExpr(
							pairExpr(pp.group.getBilinearMap(), hViStar.get(i), providerPublicKey.digitsig_public_y, v_iStarVar.get(i)),
							pairExpr(pp.group.getBilinearMap(), pp.w, providerPublicKey.digitsig_g2, v_iStarBlindersVar.get(i))
					)));
		}

		//ctrace
		for (int i=0;i<rho;i++) {
			problems.add(equalExpr(ctraceRandomness.get(i), powExpr(pp.w, r_iVar.get(i))));
			problems.add(equalExpr(ctraceCiphertexts.get(i), prodExpr(powExpr(ctraceRandomness.get(i), eskVar), powExpr(pp.w, esk_i_starVar.get(i)))));
		}

		//esk* base decomp
		exprs = new ArrayList<>();
		for (int i=0;i<rho;i++)
			exprs.add(powExpr(base_to_the_i.get(i), esk_i_starVar.get(i)));
		exprs.add(powExpr(oneInZp.inv(), eskStarVar));
		problems.add(equalExpr(zp.getZeroElement().toAdditiveGroupElement(), prodExpr(exprs.stream().toArray(ArithGroupElementExpression[]::new))));

		//esk_i* < base
		for (int i=0; i<rho;i++) {
			problems.add(equalExpr(
					prodExpr(
							pairExpr(pp.group.getBilinearMap(), blindedSigmaEskiStar.get(i), providerPublicKey.digitsig_g2),
							pairExpr(pp.group.getBilinearMap(), hEskiStar.get(i).inv(), providerPublicKey.digitsig_public_x)
					), prodExpr(
							pairExpr(pp.group.getBilinearMap(), hEskiStar.get(i), providerPublicKey.digitsig_public_y, esk_i_starVar.get(i)),
							pairExpr(pp.group.getBilinearMap(), pp.w, providerPublicKey.digitsig_g2, esk_iStarBlindersVar.get(i))
					)));
		}

		return new GeneralizedSchnorrProtocolFactory(problems.stream().toArray(ArithComparisonExpression[]::new), zp);
	}

	static GeneralizedSchnorrProtocol getSpendDeductSchnorrProverProtocol(IncentiveSystemPublicParameters pp, IncentiveProviderPublicKey providerPublicKey, GroupElement dsid, List<GroupElement> ctraceRandomness, List<GroupElement> ctraceCiphertexts, Zp.ZpElement k, Zp.ZpElement gamma, int rho, List<GroupElement> blindedSigmaViStar, List<GroupElement> hViStar, List<GroupElement> blindedSigmaEskiStar, List<GroupElement> hEskiStar, GroupElement commitmentC0, Zp.ZpElement c0, Zp.ZpElement c1, GroupElement Cpre0blinded /*Cpre0 * h6^Cpre0blinderVar*/, GroupElement Cpre0powU, GroupElement Cpre1PowU, Zp.ZpElement eskIsr,
																		  Zp.ZpElement usk, Zp.ZpElement v, Zp.ZpElement z, Zp.ZpElement zStar, Zp.ZpElement t, Zp.ZpElement tStar, Zp.ZpElement uStar, Zp.ZpElement esk, Zp.ZpElement eskStar, List<Zp.ZpElement> esk_i_star, List<Zp.ZpElement> r_i, List<Zp.ZpElement> esk_i_star_blinder, List<Zp.ZpElement> v_iStar, List<Zp.ZpElement> v_i_star_blinder, Zp.ZpElement eskUsrStar, Zp.ZpElement dsrnd0, Zp.ZpElement dsrnd0Star, Zp.ZpElement dsrnd1, Zp.ZpElement dsrnd1Star, Zp.ZpElement Cpre0blinder) {
		GeneralizedSchnorrProtocolFactory schnorrFac = getSpendDeductSchnoorProtocolFactory(pp, providerPublicKey, dsid, ctraceRandomness, ctraceCiphertexts, k, gamma, rho, blindedSigmaViStar, hViStar, blindedSigmaEskiStar, hEskiStar, commitmentC0, c0, c1, Cpre0blinded /*Cpre0 * h6^Cpre0blinderVar*/, Cpre0powU, Cpre1PowU, eskIsr);

		HashMap<String, Zp.ZpElement> witnessMapping = new HashMap<>();
		witnessMapping.put("usk", usk);
		witnessMapping.put("v", v);
		witnessMapping.put("z", z);
		witnessMapping.put("zStar", zStar);
		witnessMapping.put("t", t);
		witnessMapping.put("tStar", tStar);
		witnessMapping.put("uStar", uStar);
		witnessMapping.put("esk", esk);
		witnessMapping.put("eskStar", eskStar);
		//List<Zp.ZpElement> esk_i_star_blinder = new ArrayList<>(); //values used to blind the signatures for digits of esk_iStar with, i.e. sigma' = \sigma * w^v_iStarBLinder
		for (int i=0;i<rho;i++) {
			witnessMapping.put("esk_" + i + "_star", esk_i_star.get(i)); //base-decomp of esk*
			witnessMapping.put("r_" + i, r_i.get(i));
			witnessMapping.put("esk_"+i+"_star_blinder", esk_i_star_blinder.get(i));
		}

		//List<Zp.ZpElement> v_iStar = SpendInstance.getUaryRepresentationOf(v.sub(k)); //base decomposition of v* = v-k
		//List<Zp.ZpElement> v_iStarBlindersVar = new ArrayList<>(); //values used to blind the signatures for digits of v_iStar with, i.e. sigma' = \sigma * w^v_iStarBLinder
		for (int i=0; i<SpendInstance.VMAX_EXPONENT; i++) {
			witnessMapping.put("v_"+i+"_star", v_iStar.get(i));
			witnessMapping.put("v_"+i+"_star_blinder", v_i_star_blinder.get(i));
		}
		witnessMapping.put("eskusrStar", eskUsrStar);
		witnessMapping.put("dsrnd0", dsrnd0);
		witnessMapping.put("dsrnd0Star", dsrnd0Star);
		witnessMapping.put("dsrnd1", dsrnd1);
		witnessMapping.put("dsrnd1Star", dsrnd1Star);

		//For the double-exponent opening
		witnessMapping.put("Cpre0blinder", Cpre0blinder); //Cpre0 * h6^Cpre0blinderVar
		witnessMapping.put("Cpre0blinderTimesUStar", Cpre0blinder.mul(uStar)); //Cpre0blinderVar*uStarVar

		return schnorrFac.createProverGeneralizedSchnorrProtocol(witnessMapping);
	}

	static GeneralizedSchnorrProtocol getSpendDeductSchnorrVerifierProtocol(IncentiveSystemPublicParameters pp, IncentiveProviderPublicKey providerPublicKey, GroupElement dsid, List<GroupElement> ctraceRandomness, List<GroupElement> ctraceCiphertexts, Zp.ZpElement k, Zp.ZpElement gamma, int rho, List<GroupElement> blindedSigmaViStar, List<GroupElement> hViStar, List<GroupElement> blindedSigmaEskiStar, List<GroupElement> hEskiStar, GroupElement commitmentC0, Zp.ZpElement c0, Zp.ZpElement c1, GroupElement Cpre0blinded /*Cpre0 * h6^Cpre0blinderVar*/, GroupElement Cpre0powU, GroupElement Cpre1PowU, Zp.ZpElement eskIsr) {
		GeneralizedSchnorrProtocolFactory schnorrFac = getSpendDeductSchnoorProtocolFactory(pp, providerPublicKey, dsid, ctraceRandomness, ctraceCiphertexts, k, gamma, rho, blindedSigmaViStar, hViStar, blindedSigmaEskiStar, hEskiStar, commitmentC0, c0, c1, Cpre0blinded /*Cpre0 * h6^Cpre0blinderVar*/, Cpre0powU, Cpre1PowU, eskIsr);
		return schnorrFac.createVerifierGeneralizedSchnorrProtocol();
	}

	
	/** Problem for expression c1 = baseExpr^expVar */
	private static GroupElementEqualityExpression getElgamalProblemA(GroupElement c1, ArithGroupElementExpression baseExpr, ZnVariable expVar) {
		return new GroupElementEqualityExpression(
				new NumberGroupElementLiteral(c1),
				new ProductGroupElementExpression(new PowerGroupElementExpression(baseExpr, expVar))
		);
	}

	/** Problem for expression c2 = gExpr^aVar * hExpr^bVar */
	private static GroupElementEqualityExpression getElgamalProblemB(GroupElement c2, ArithGroupElementExpression gExpr, ZnVariable aVar, ArithGroupElementExpression hExpr, ZnVariable bVar) {
		ProductGroupElementExpression rhs3bExpr = new ProductGroupElementExpression(
				new PowerGroupElementExpression(gExpr, aVar),
				new PowerGroupElementExpression(hExpr, bVar)
		);
		return new GroupElementEqualityExpression(new NumberGroupElementLiteral(c2), rhs3bExpr);
	}



	/* Prover and Verifier protocols using PoPK */

/*	static SigmaProtocol getSpendDeductProverProtocol(IncentiveSystemPublicParameters pp, Zp.ZpElement c, Zp.ZpElement gamma, PSExtendedVerificationKey pk, PSSignature blindedSig, Zp.ZpElement k, ElgamalCipherText ctrace, PedersenCommitmentValue commitment, PedersenCommitmentPair commitmentOfValue, Zp.ZpElement usk, Zp.ZpElement dldsid, Zp.ZpElement dsrnd, Zp.ZpElement dldsidStar, Zp.ZpElement dsrndStar, Zp.ZpElement r, Zp.ZpElement rC, Zp.ZpElement rPrime, Zp.ZpElement v, PedersenCommitmentValue rangeCommitment, Zp.ZpElement rangeRandomness) {
		GeneralizedSchnorrProtocol schnorr = getSpendDeductSchnorrProverProtocol(pp, c, gamma, pk, blindedSig, k, ctrace, commitment, commitmentOfValue, usk, dldsid, dsrnd, dldsidStar, dsrndStar, r, rC, rPrime, v, , );
		SigmaProtocolPolicyFact schnorrPolicyFact = new SigmaProtocolPolicyFact(schnorr, 1);

		ZeroToUPowLRangeProofProtocol rangeProof = getSpendDeductRangeProverProtocol(pp, pk, rangeCommitment, rangeRandomness, (Zp.ZpElement) v.sub(k));
		SigmaProtocolPolicyFact rangePolicyFact = new SigmaProtocolPolicyFact(rangeProof, 2);

		ThresholdPolicy policy = new ThresholdPolicy(2, schnorrPolicyFact, rangePolicyFact);

		return new ProofOfPartialKnowledgeProtocol(
				new ProofOfPartialKnowledgePublicParameters(
						new ShamirSecretSharingSchemeProvider(),
						new Zp(pp.group.getG1().size())
				), policy
		);
	}

	static SigmaProtocol getSpendDeductVerifierProtocol(IncentiveSystemPublicParameters pp, Zp.ZpElement c, Zp.ZpElement gamma, PSExtendedVerificationKey pk, PSSignature blindedSig, Zp.ZpElement k, ElgamalCipherText ctrace, PedersenCommitmentValue commitment, PedersenCommitmentValue commitmentOnV, ArbitraryRangeProofPublicParameters rangePP) {
		GeneralizedSchnorrProtocol schnorr = getSpendDeductSchnorrVerifierProtocol(pp, c, gamma, pk, blindedSig, k, ctrace, commitment, commitmentOnV);
		SigmaProtocolPolicyFact schnorrPolicyFact = new SigmaProtocolPolicyFact(schnorr, 1);

		ZeroToUPowLRangeProofProtocol rangeProof = getSpendDeductRangeVerifierProtocol(rangePP);
		SigmaProtocolPolicyFact rangePolicyFact = new SigmaProtocolPolicyFact(rangeProof, 2);

		ThresholdPolicy policy = new ThresholdPolicy(2, schnorrPolicyFact, rangePolicyFact);

		return new ProofOfPartialKnowledgeProtocol(
				new ProofOfPartialKnowledgePublicParameters(
						new ShamirSecretSharingSchemeProvider(),
						new Zp(pp.group.getG1().size())
				), policy
		);
	}*/
}
