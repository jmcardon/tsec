object SignatureExamples {

  import tsec.common._
  import tsec.signature.imports._
  import cats.effect.Sync
  import cats.syntax.all._

  val toSign: Array[Byte] = "hiThere!".utf8Bytes

  /** Signature Example:
    * JCASignerPure will take any F[_]: Sync
    */
  def pureSign[F[_]](implicit F: Sync[F]): F[Boolean] =
    for {
      keyPair   <- F.fromEither(SHA256withRSA.generateKeyPair)
      signed    <- JCASigner.sign(toSign, keyPair.privateKey)
      verified  <- JCASigner.verifyKI(toSign, signed, keyPair.publicKey)
      verified2 <- JCASigner.verifyK(toSign, signed, keyPair.publicKey)
    } yield verified2

  /*
  Signature example with Either
   */
  val sig: Either[Throwable, Boolean] = for {
    keyPair   <- SHA256withECDSA.generateKeyPair
    signed    <- JCASignerImpure.sign(toSign, keyPair.privateKey)
    verified  <- JCASignerImpure.verifyKI(toSign, signed, keyPair.publicKey) //Verify with the particular instance
    verified2 <- JCASignerImpure.verifyK(toSign, signed, keyPair.publicKey) //Or directly with arrays
  } yield verified2

}
