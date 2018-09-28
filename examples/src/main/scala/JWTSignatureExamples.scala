object JWTSignatureExamples {

  import cats.effect.Sync
  import cats.syntax.all._
  import tsec.jws.signature._
  import tsec.jwt._
  import tsec.signature.jca._

  /** Example usage */
  val claims = JWTClaims()

  def jwtStuffMonadic[F[_]](implicit F: Sync[F]): F[JWTSig[SHA256withECDSA]] =
    for {
      keyPair      <- SHA256withECDSA.generateKeyPair[F]
      jwtSig       <- JWTSig.signAndBuild[F, SHA256withECDSA](claims, keyPair.privateKey) //ToInstance
      jwtSigString <- JWTSig.signToString[F, SHA256withECDSA](claims, keyPair.privateKey)
      verified1    <- JWTSig.verifyK[F, SHA256withECDSA](jwtSigString, keyPair.publicKey)
      verified2    <- JWTSig.verifyKI[F, SHA256withECDSA](jwtSig, keyPair.publicKey)
    } yield verified2

  val jwtStuff: Either[Throwable, JWTSig[SHA256withECDSA]] = for {
    keyPair      <- SHA256withECDSA.generateKeyPair[SigErrorM]
    jwtSig       <- JWTSigImpure.signAndBuild[SHA256withECDSA](claims, keyPair.privateKey) //ToInstance
    jwtSigString <- JWTSigImpure.signToString(claims, keyPair.privateKey)
    verified1    <- JWTSigImpure.verifyK(jwtSigString, keyPair.publicKey)
    verified2    <- JWTSigImpure.verifyKI(jwtSig, keyPair.publicKey)
  } yield verified2

}
