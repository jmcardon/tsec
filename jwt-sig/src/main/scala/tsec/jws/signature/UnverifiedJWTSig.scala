package tsec.jws.signature

import java.time.Instant

import cats.effect.Sync
import tsec.jwt.JWTClaims
import tsec.jwt.algorithms.JWTSigAlgo
import tsec.signature.CryptoSignature
import tsec.signature.jca.{SigCertificate, SigErrorM, SigPublicKey}
import cats.syntax.flatMap._
import tsec.jws.JWSSerializer
import tsec.common._

final case class UnverifiedJWTSig[A: JWTSigAlgo](
    header: JWSSignedHeader[A],
    body: JWTClaims,
    signature: CryptoSignature[A]
) {
  def serialized(implicit hs: JWSSerializer[JWSSignedHeader[A]]): String =
    s"${hs.toB64URL(header)}.${JWTClaims.toB64URL(body)}.${signature.toB64UrlString}"
}

object UnverifiedJWTSig {
  def unverified[F[_], A: JWTSigAlgo](jwt: String)(implicit F: Sync[F], sigCV: JWSSigCV[F, A]): F[UnverifiedJWTSig[A]] =
    sigCV.extractRaw(jwt)

  def verifyK[F[_], A: JWTSigAlgo](
      jwt: UnverifiedJWTSig[A],
      pubKey: SigPublicKey[A]
  )(implicit F: Sync[F], sigCV: JWSSigCV[F, A], hs: JWSSerializer[JWSSignedHeader[A]]): F[JWTSig[A]] =
    F.delay(Instant.now()).flatMap(sigCV.verify(jwt.serialized, pubKey, _))

  def verifyC[F[_], A: JWTSigAlgo](
      jwt: UnverifiedJWTSig[A],
      cert: SigCertificate[A]
  )(implicit F: Sync[F], sigCV: JWSSigCV[F, A], hs: JWSSerializer[JWSSignedHeader[A]]): F[JWTSig[A]] =
    F.delay(Instant.now()).flatMap(sigCV.verifyCert(jwt.serialized, cert, _))
}

object UnverifiedJWTSigImpure {
  def unverified[A: JWTSigAlgo](jwt: String)(implicit sigCV: JWSSigCV[SigErrorM, A]): SigErrorM[UnverifiedJWTSig[A]] =
    sigCV.extractRaw(jwt)

  def verifyK[A: JWTSigAlgo](
      jwt: UnverifiedJWTSig[A],
      pubKey: SigPublicKey[A]
  )(implicit sigCV: JWSSigCV[SigErrorM, A], hs: JWSSerializer[JWSSignedHeader[A]]): SigErrorM[JWTSig[A]] =
    sigCV.verify(jwt.serialized, pubKey, Instant.now())

  def verifyC[A: JWTSigAlgo](
      jwt: UnverifiedJWTSig[A],
      cert: SigCertificate[A]
  )(implicit sigCV: JWSSigCV[SigErrorM, A], hs: JWSSerializer[JWSSignedHeader[A]]): SigErrorM[JWTSig[A]] =
    sigCV.verifyCert(jwt.serialized, cert, Instant.now())
}
