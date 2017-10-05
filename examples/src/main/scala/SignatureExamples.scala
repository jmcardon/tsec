import cats.effect.{IO, Sync}

object SignatureExamples {

  import tsec.signature.imports._

  /*
  Signature example with Either
   */
  import tsec.common._
  val toSign                               = "hiThere!".utf8Bytes
  val instance: JCASigner[SHA256withECDSA] = JCASigner[SHA256withECDSA]
  val sig: Either[Throwable, Boolean] = for {
    keyPair   <- SHA256withECDSA.generateKeyPair
    signed    <- instance.sign(toSign, keyPair.privateKey)
    verified  <- instance.verifyKI(toSign, signed, keyPair.publicKey) //Verify with the particular instance
    verified2 <- instance.verifyK(toSign, signed, keyPair.publicKey) //Or directly with arrays
  } yield verified2

  /** Signature Example with IO:
    * JCASignerPure will take any F[_]: Sync
    */
  val instancePure: JCASignerPure[IO, SHA256withRSA] = JCASignerPure[IO, SHA256withRSA]
  val ioSign: IO[Boolean] = for {
    keyPair   <- Sync[IO].fromEither(SHA256withRSA.generateKeyPair)
    signed    <- instancePure.sign(toSign, keyPair.privateKey)
    verified  <- instancePure.verifyKI(toSign, signed, keyPair.publicKey)
    verified2 <- instancePure.verifyK(toSign, signed, keyPair.publicKey)
  } yield verified2

}
