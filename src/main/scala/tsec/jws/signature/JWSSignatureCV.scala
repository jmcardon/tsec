package tsec.jws.signature

import cats.data.EitherT
import cats.effect.Sync
import cats.syntax.all._
import shapeless._
import tsec.core.ByteUtils._
import tsec.jws.{JWSSerializer, JWSSignature}
import tsec.jwt.algorithms.JWTSigAlgo
import tsec.jwt.claims.JWTClaims
import tsec.signature.core._
import tsec.signature.instance._
import java.time.Instant

protected[tsec] final class JWSSignatureCV[F[_], A: SigAlgoTag](
    implicit hs: JWSSerializer[JWSSignedHeader[A]],
    aux: ByteAux[A],
    jwsSigAlgo: JWTSigAlgo[A],
    sigDSL: SignerPrograms.Aux[F, A, SigPublicKey[A], SigPrivateKey[A], SigCertificate[A]],
    M: Sync[F]
) {

  /*
  Generic Error.
  Any mishandling of the errors could leak information to an attacker.
   */
  private def defaultError: SignatureError = SignatureError("Could not verify signature")

  def signAndBuild(header: JWSSignedHeader[A], body: JWTClaims, sigPrivateKey: SigPrivateKey[A]): F[JWTSig[A]] = {
    val toSign = hs.toB64URL(header) + "." + JWTClaims.toB64URL(body)
    for {
      signature <- sigDSL.sign(toSign.asciiBytes, sigPrivateKey)
      concat    <- jwsSigAlgo.jcaToConcat(aux.to(signature).head)
    } yield JWTSig(header, body, JWSSignature[A](concat))
  }

  def signToString(header: JWSSignedHeader[A], body: JWTClaims, sigPrivateKey: SigPrivateKey[A]): F[String] = {
    val toSign = hs.toB64URL(header) + "." + JWTClaims.toB64URL(body)
    for {
      signature <- sigDSL.sign(toSign.asciiBytes, sigPrivateKey)
      concat    <- jwsSigAlgo.jcaToConcat(aux.to(signature).head)
    } yield toSign + "." + concat.toB64UrlString
  }

  def verifyK(
      jwt: String,
      extract: JWSSignedHeader[A] => SigPublicKey[A]
  ): F[JWTSig[A]] = {
    val now                  = Instant.now()
    val split: Array[String] = jwt.split("\\.", 3)
    if (split.length != 3)
      M.raiseError[JWTSig[A]](defaultError)
    else {
      val providedBytes: Array[Byte] = split(2).base64UrlBytes
      for {
        sigExtract <- jwsSigAlgo.concatToJCA(providedBytes)
        header     <- M.fromEither(hs.fromUtf8Bytes(split(0).base64UrlBytes).left.map(_ => defaultError))
        bool       <- sigDSL.verifyK(sigExtract, extract(header))
        body <- M.ensure(M.fromEither(JWTClaims.fromB64URL(split(1))))(defaultError)(
          claims => bool && claims.isAfterNBF(now) && claims.isNotExpired(now) && claims.isValidIssued(now)
        )
      } yield JWTSig(header, body, JWSSignature(providedBytes))
    }
  }

  def verifyC(
      jwt: String,
      extract: JWSSignedHeader[A] => SigCertificate[A]
  ): F[JWTSig[A]] = {
    val now                  = Instant.now()
    val split: Array[String] = jwt.split("\\.", 3)
    if (split.length != 3)
      M.raiseError[JWTSig[A]](defaultError)
    else {
      val providedBytes: Array[Byte] = split(2).base64UrlBytes
      for {
        sigExtract <- jwsSigAlgo.concatToJCA(providedBytes)
        header     <- M.fromEither(hs.fromUtf8Bytes(split(0).base64UrlBytes).left.map(_ => defaultError))
        bool       <- sigDSL.verifyC(sigExtract, extract(header))
        body <- M.ensure(M.fromEither(JWTClaims.fromB64URL(split(1))))(defaultError)(
          claims => bool && claims.isAfterNBF(now) && claims.isNotExpired(now) && claims.isValidIssued(now)
        )
      } yield JWTSig(header, body, JWSSignature(providedBytes))
    }
  }
}

object JWSSignatureCV {
  implicit def genCV[F[_], A: SigAlgoTag](
      implicit hs: JWSSerializer[JWSSignedHeader[A]],
      aux: ByteAux[A],
      jwsSigAlgo: JWTSigAlgo[A],
      sigDSL: SignerPrograms.Aux[F, A, SigPublicKey[A], SigPrivateKey[A], SigCertificate[A]],
      M: Sync[F]
  ): JWSSignatureCV[F, A] = new JWSSignatureCV[F, A]()
}
