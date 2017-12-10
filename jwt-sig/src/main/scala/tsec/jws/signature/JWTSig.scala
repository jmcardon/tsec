package tsec.jws.signature

import java.time.Instant
import tsec.common._
import cats.effect.Sync
import tsec.jws.{JWSJWT, JWSSerializer}
import tsec.signature.imports._
import tsec.jwt.JWTClaims
import tsec.jwt.algorithms.JWTSigAlgo
import tsec.signature.core.CryptoSignature
import cats.syntax.all._

case class JWTSig[A](header: JWSSignedHeader[A], body: JWTClaims, signature: CryptoSignature[A])
    extends JWSJWT[A, CryptoSignature] {
  def toEncodedString(implicit hs: JWSSerializer[JWSSignedHeader[A]]): String =
    hs.toB64URL(header) + "." + JWTClaims.toB64URL(body) + "." + signature.toB64UrlString
}

object JWTSig {

  def signAndBuild[A: JWTSigAlgo](body: JWTClaims, sigPrivateKey: SigPrivateKey[A])(
      implicit sigCV: JWSSigCV[SigErrorM, A]
  ): SigErrorM[JWTSig[A]] = sigCV.signAndBuild(JWSSignedHeader[A](), body, sigPrivateKey)

  def signAndBuild[A: JWTSigAlgo](header: JWSSignedHeader[A], body: JWTClaims, sigPrivateKey: SigPrivateKey[A])(
      implicit sigCV: JWSSigCV[SigErrorM, A]
  ): SigErrorM[JWTSig[A]] = sigCV.signAndBuild(header, body, sigPrivateKey)

  def signToString[A: JWTSigAlgo](header: JWSSignedHeader[A], body: JWTClaims, sigPrivateKey: SigPrivateKey[A])(
      implicit sigCV: JWSSigCV[SigErrorM, A]
  ): SigErrorM[String] = sigCV.signToString(header, body, sigPrivateKey)

  def signToString[A: JWTSigAlgo](body: JWTClaims, sigPrivateKey: SigPrivateKey[A])(
      implicit sigCV: JWSSigCV[SigErrorM, A]
  ): SigErrorM[String] = sigCV.signToString(JWSSignedHeader[A](), body, sigPrivateKey)

  def verifyK[A: JWTSigAlgo](
      jwt: String,
      pubKey: SigPublicKey[A]
  )(implicit sigCV: JWSSigCV[SigErrorM, A]): SigErrorM[JWTSig[A]] = sigCV.verifyK(jwt, pubKey, Instant.now())

  def verifyC[A: JWTSigAlgo](
      jwt: String,
      cert: SigCertificate[A]
  )(implicit sigCV: JWSSigCV[SigErrorM, A]): SigErrorM[JWTSig[A]] = sigCV.verifyC(jwt, cert, Instant.now())

  def verifyKI[A: JWTSigAlgo](
      jwt: JWTSig[A],
      extract: SigPublicKey[A]
  )(implicit sigCV: JWSSigCV[SigErrorM, A], hs: JWSSerializer[JWSSignedHeader[A]]): SigErrorM[JWTSig[A]] =
    verifyK[A](jwt.toEncodedString, extract)

  def verifyCI[A: JWTSigAlgo](
      jwt: JWTSig[A],
      cert: SigCertificate[A]
  )(implicit sigCV: JWSSigCV[SigErrorM, A]): SigErrorM[JWTSig[A]] =
    sigCV.verifyC(jwt.toEncodedString, cert, Instant.now())

}

object JWTSigSync {

  def signAndBuild[F[_]: Sync, A: JWTSigAlgo](
      header: JWSSignedHeader[A],
      body: JWTClaims,
      sigPrivateKey: SigPrivateKey[A]
  )(implicit sigCV: JWSSigCV[F, A]): F[JWTSig[A]] = sigCV.signAndBuild(header, body, sigPrivateKey)

  def signToString[F[_]: Sync, A: JWTSigAlgo](
      header: JWSSignedHeader[A],
      body: JWTClaims,
      sigPrivateKey: SigPrivateKey[A]
  )(implicit sigCV: JWSSigCV[F, A]): F[String] = sigCV.signToString(header, body, sigPrivateKey)

  def verifyK[F[_], A: JWTSigAlgo](
      jwt: String,
      pubKey: SigPublicKey[A]
  )(implicit F: Sync[F], sigCV: JWSSigCV[F, A]): F[JWTSig[A]] =
    F.delay(Instant.now()).flatMap(sigCV.verifyK(jwt, pubKey, _))

  def verifyC[F[_], A: JWTSigAlgo](
      jwt: String,
      cert: SigCertificate[A]
  )(implicit F: Sync[F], sigCV: JWSSigCV[F, A]): F[JWTSig[A]] =
    F.delay(Instant.now()).flatMap(sigCV.verifyC(jwt, cert, _))

  def verifyKI[F[_], A: JWTSigAlgo](
      jwt: JWTSig[A],
      extract: SigPublicKey[A]
  )(implicit F: Sync[F], sigCV: JWSSigCV[F, A], hs: JWSSerializer[JWSSignedHeader[A]]): F[JWTSig[A]] =
    verifyK[F, A](jwt.toEncodedString, extract)

  def verifyCI[F[_], A: JWTSigAlgo](
    jwt: JWTSig[A],
    extract: SigCertificate[A]
  )(implicit F: Sync[F], sigCV: JWSSigCV[F, A], hs: JWSSerializer[JWSSignedHeader[A]]): F[JWTSig[A]] =
    verifyC[F, A](jwt.toEncodedString, extract)

}
