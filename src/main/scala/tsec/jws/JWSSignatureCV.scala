package tsec.jws

import java.security.PrivateKey

import cats.data.EitherT
import cats.effect.{Async, Sync}
import com.softwaremill.tagging.@@
import tsec.jws.algorithms.JWTSigAlgo
import tsec.jws.header.JWSJOSESig
import tsec.jws.signature.{JWSSignature, SigVerificationError}
import tsec.jwt.claims.JWTClaims
import tsec.signature.core._
import tsec.signature.instance.JCASigner
import cats.syntax.all._
import io.circe.Error
import tsec.core.ByteUtils
import tsec.core.ByteUtils.ByteAux
import shapeless._

class JWSSignatureCV[F[_], A: SigAlgoTag](
    implicit hs: JWSSerializer[JWSJOSESig[A]],
    aux: ByteAux[A],
    jwsSigAlgo: JWTSigAlgo[A],
    sigDSL: SignerDSL[F, A],
    M: Sync[F]
) {
  import sigDSL.algebra._

  /*
  Generic Error.
  Any mishandling of the errors could leak information to an attacker.
   */
  private def defaultError: SigVerificationError = SigVerificationError("Could not verify signature")

  def signAndBuild(header: JWSJOSESig[A], body: JWTClaims, sigPrivateKey: SigPrivateKey[PrivK @@ A]): F[JWTSig[A]] = {
    val toSign = hs.toB64URL(header) + "." + JWTClaims.jwsSerializer.toB64URL(body)
    for {
      signature <- sigDSL.sign(toSign.asciiBytes, sigPrivateKey)
      concat    <- jwsSigAlgo.jcaToConcat(aux.to(signature).head)
    } yield JWTSig(header, body, JWSSignature(aux.from(concat :: HNil)))
  }

  def signToString(header: JWSJOSESig[A], body: JWTClaims, sigPrivateKey: SigPrivateKey[PrivK @@ A]): F[String] = {
    val toSign = hs.toB64URL(header) + "." + JWTClaims.jwsSerializer.toB64URL(body)
    for {
      signature <- sigDSL.sign(toSign.asciiBytes, sigPrivateKey)
      concat    <- jwsSigAlgo.jcaToConcat(aux.to(signature).head)
    } yield toSign + "." + concat.toB64UrlString
  }

  def verifyK(
      jwt: String,
      extract: JWSJOSESig[A] => SigPublicKey[PubK @@ A]
  ): EitherT[F, SigVerificationError, JWTSig[A]] = {
    val split: Array[String] = jwt.split("\\.", 3)
    if (split.length != 3)
      EitherT.left(M.pure(defaultError))
    else {
      val providedBytes: Array[Byte] = split(2).base64Bytes
      for {
        sigExtract <- EitherT.liftT(jwsSigAlgo.concatToJCA(providedBytes))
        h <- EitherT
          .fromEither(hs.fromUtf8Bytes(split(0).base64Bytes))
          .leftMap(_ => defaultError)
        publicKey = extract(h)
        bool <- EitherT.liftT(sigDSL.verifyK(sigExtract, publicKey))
        _    <- EitherT.cond[F](bool, (), defaultError)
        body <- EitherT
          .fromEither(JWTClaims.jwsSerializer.fromB64URL(split(1)))
          .leftMap(_ => defaultError)
      } yield JWTSig(h, body, JWSSignature(aux.from(providedBytes :: HNil)))
    }
  }

  def verifyC(
    jwt: String,
    extract: JWSJOSESig[A] => SigCertificate[Cert @@ A]
  ): EitherT[F, SigVerificationError, JWTSig[A]] = {
    val split: Array[String] = jwt.split("\\.", 3)
    if (split.length != 3)
      EitherT.left(M.pure(defaultError))
    else {
      val providedBytes: Array[Byte] = split(2).base64Bytes
      for {
        sigExtract <- EitherT.liftT(jwsSigAlgo.concatToJCA(providedBytes))
        h <- EitherT
          .fromEither(hs.fromUtf8Bytes(split(0).base64Bytes))
          .leftMap(_ => defaultError)
        certificate = extract(h)
        bool <- EitherT.liftT(sigDSL.verifyC(sigExtract, certificate))
        _    <- EitherT.cond[F](bool, (), defaultError)
        body <- EitherT
          .fromEither(JWTClaims.jwsSerializer.fromB64URL(split(1)))
          .leftMap(_ => defaultError)
      } yield JWTSig(h, body, JWSSignature(aux.from(providedBytes :: HNil)))
    }
  }
}
