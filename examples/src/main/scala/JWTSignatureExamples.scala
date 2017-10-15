object JWTSignatureExamples {

  import tsec.jwt._
  import tsec.jws.signature._
  import tsec.signature.imports._

  /** Example usage */
  val claims = JWTClaims()
  val jwtStuff: Either[Throwable, JWTSig[SHA256withECDSA]] = for {
    keyPair      <- SHA256withECDSA.generateKeyPair
    jwtSig       <- JWTSig.signAndBuild[SHA256withECDSA](claims, keyPair.privateKey) //ToInstance
    jwtSigString <- JWTSig.signToString(claims, keyPair.privateKey)
    verified1    <- JWTSig.verifyK(jwtSigString, keyPair.publicKey)
    verified2    <- JWTSig.verifyKI(jwtSig, keyPair.publicKey)
  } yield verified2

}
