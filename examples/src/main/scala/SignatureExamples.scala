object SignatureExamples {

  import tsec.common._
  import tsec.signature.core._
  import tsec.signature.imports._
  import cats.effect.Sync
  import cats.syntax.all._

  val toSign: Array[Byte] = "hiThere!".utf8Bytes

  /** Signature Example:
    */
  def pureSign[F[_]](implicit F: Sync[F]): F[(CryptoSignature[SHA256withRSA], Boolean)] =
    for {
      keyPair  <- F.fromEither(SHA256withRSA.generateKeyPair)
      signed   <- SHA256withRSA.sign[F](toSign, keyPair.privateKey)
      verified <- SHA256withRSA.verify[F](toSign, signed, keyPair.publicKey)
    } yield (signed, verified)

  /*
  Signature example with Either
   */
  val sig: Either[Throwable, Boolean] = for {
    keyPair <- SHA256withECDSA.generateKeyPair
    signed  <- SHA256withECDSA.sign[SigErrorM](toSign, keyPair.privateKey)
    verified <- SHA256withECDSA
      .verify[SigErrorM](toSign, signed, keyPair.publicKey) //Verify with the particular instance
  } yield verified

}
