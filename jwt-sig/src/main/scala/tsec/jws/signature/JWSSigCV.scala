package tsec.jws.signature

import cats.syntax.all._
import tsec.common.ByteUtils._
import tsec.jws.{JWSSerializer, JWSSignature}
import tsec.jwt.algorithms.JWTSigAlgo
import tsec.signature.core._
import tsec.signature.imports._
import java.time.Instant

import cats.instances.either._
import cats.MonadError
import tsec.jwt.JWTClaims

sealed abstract class JWSSigCV[F[_], A](
    implicit hs: JWSSerializer[JWSSignedHeader[A]],
    aux: ByteAux[A],
    jwsSigAlgo: JWTSigAlgo[A],
    sigDSL: SignerPrograms.Aux[F, A, SigPublicKey[A], SigPrivateKey[A], SigCertificate[A]],
    M: MonadError[F, Throwable]
) {

  /*
  Generic Error.
  Any mishandling of the errors could leak information to an attacker.
   */
  private def defaultError: GeneralSignatureError = GeneralSignatureError("Could not verify signature")

  def signAndBuild(header: JWSSignedHeader[A], body: JWTClaims, sigPrivateKey: SigPrivateKey[A]): F[JWTSig[A]] = {
    val toSign = hs.toB64URL(header) + "." + JWTClaims.toB64URL(body)
    for {
      signature <- sigDSL.sign(toSign.asciiBytes, sigPrivateKey)
      concat    <- jwsSigAlgo.jcaToConcat[F](aux.to(signature).head)
    } yield JWTSig(header, body, JWSSignature[A](concat))
  }

  def signToString(header: JWSSignedHeader[A], body: JWTClaims, sigPrivateKey: SigPrivateKey[A]): F[String] = {
    val toSign = hs.toB64URL(header) + "." + JWTClaims.toB64URL(body)
    for {
      signature <- sigDSL.sign(toSign.asciiBytes, sigPrivateKey)
      concat    <- jwsSigAlgo.jcaToConcat[F](aux.to(signature).head)
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
      val toSign                     = (split(0) + "." + split(1)).asciiBytes
      for {
        sigExtract <- jwsSigAlgo.concatToJCA[F](providedBytes)
        header     <- M.fromEither(hs.fromUtf8Bytes(split(0).base64UrlBytes).left.map(_ => defaultError))
        bool       <- sigDSL.verifyK(toSign, sigExtract, extract(header))
        body <- M.ensure(M.fromEither(JWTClaims.fromB64URL(split(1))))(defaultError)(
          claims => bool && claims.isAfterNBF(now) && claims.isNotExpired(now) && claims.isValidIssued(now)
        )
      } yield JWTSig(header, body, JWSSignature(providedBytes))
    }
  }

  def verifyK(
      jwt: String,
      pubKey: SigPublicKey[A]
  ): F[JWTSig[A]] = {
    val now                  = Instant.now()
    val split: Array[String] = jwt.split("\\.", 3)
    if (split.length != 3)
      M.raiseError[JWTSig[A]](defaultError)
    else {
      val providedBytes: Array[Byte] = split(2).base64UrlBytes
      val toSign                     = (split(0) + "." + split(1)).asciiBytes
      for {
        sigExtract <- jwsSigAlgo.concatToJCA[F](providedBytes)
        header     <- M.fromEither(hs.fromUtf8Bytes(split(0).base64UrlBytes).left.map(_ => defaultError))
        bool       <- sigDSL.verifyK(toSign, sigExtract, pubKey)
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
      val toSign                     = (split(0) + "." + split(1)).asciiBytes
      for {
        sigExtract <- jwsSigAlgo.concatToJCA[F](providedBytes)
        header     <- M.fromEither(hs.fromUtf8Bytes(split(0).base64UrlBytes).left.map(_ => defaultError))
        bool       <- sigDSL.verifyC(toSign, sigExtract, extract(header))
        body <- M.ensure(M.fromEither(JWTClaims.fromB64URL(split(1))))(defaultError)(
          claims => bool && claims.isAfterNBF(now) && claims.isNotExpired(now) && claims.isValidIssued(now)
        )
      } yield JWTSig(header, body, JWSSignature(providedBytes))
    }
  }

  def verifyC(
      jwt: String,
      cert: SigCertificate[A]
  ): F[JWTSig[A]] = {
    val now                  = Instant.now()
    val split: Array[String] = jwt.split("\\.", 3)
    if (split.length != 3)
      M.raiseError[JWTSig[A]](defaultError)
    else {
      val providedBytes: Array[Byte] = split(2).base64UrlBytes
      val toSign                     = (split(0) + "." + split(1)).asciiBytes
      for {
        sigExtract <- jwsSigAlgo.concatToJCA[F](providedBytes)
        header     <- M.fromEither(hs.fromUtf8Bytes(split(0).base64UrlBytes).left.map(_ => defaultError))
        bool       <- sigDSL.verifyC(toSign, sigExtract, cert)
        body <- M.ensure(M.fromEither(JWTClaims.fromB64URL(split(1))))(defaultError)(
          claims => bool && claims.isAfterNBF(now) && claims.isNotExpired(now) && claims.isValidIssued(now)
        )
      } yield JWTSig(header, body, JWSSignature(providedBytes))
    }
  }
}

object JWSSigCV {
  implicit def genCVPure[F[_], A: SigAlgoTag](
      implicit hs: JWSSerializer[JWSSignedHeader[A]],
      aux: ByteAux[A],
      jwsSigAlgo: JWTSigAlgo[A],
      sigDSL: JCASignerPure[F, A],
      M: MonadError[F, Throwable]
  ): JWSSigCV[F, A] = new JWSSigCV[F, A]() {}

  implicit def genCVImpure[A: SigAlgoTag](
      implicit hs: JWSSerializer[JWSSignedHeader[A]],
      aux: ByteAux[A],
      jwsSigAlgo: JWTSigAlgo[A],
      sigDSL: JCASigner[A]
  ): JWSSigCV[SigErrorM, A] = new JWSSigCV[SigErrorM, A]() {}
}
