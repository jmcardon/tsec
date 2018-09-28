object MacExamples {

  /** Example message authentication: Note, will use byteutils */
  import cats.effect.IO
  import tsec.common._
  import tsec.mac._
  import tsec.mac.jca._
  //Necessary in 2.11
  import cats.syntax.either._

  type ET[PhoneHome] = Either[Throwable, PhoneHome]

  val toMac: Array[Byte] = "hi!".utf8Bytes

  val `mac'd`: Either[Throwable, Boolean] = for {
    key      <- HMACSHA256.generateKey[MacErrorM]               //Generate our key.
    macValue <- HMACSHA256.sign[ET](toMac, key)                 //Generate our MAC bytes
    verified <- HMACSHA256.verifyBool[ET](toMac, macValue, key) //Verify a byte array with a signed, typed instance
  } yield verified

  import cats.effect.Sync
  import cats.syntax.all._

  /** For Interpretation into any F */
  def `mac'd-pure`[F[_]: Sync]: F[Boolean] =
    for {
      key      <- HMACSHA256.generateKey[F]                      //Generate our key.
      macValue <- HMACSHA256.sign[F](toMac, key)                 //Generate our MAC bytes
      verified <- HMACSHA256.verifyBool[F](toMac, macValue, key) //Verify a byte array with a signed, typed instance
    } yield verified

  /** Using the typeclass [[MessageAuth]],
    * JCASigner is simply the class over java secret keys
    *
    */
  def usingTypeclass[F[_]: Sync, A](mToSign: Array[Byte], key: MacSigningKey[A])(
      implicit messageAuth: JCAMessageAuth[F, A]
  ): F[Boolean] =
    for {
      signed   <- messageAuth.sign(mToSign, key)
      verified <- messageAuth.verifyBool(mToSign, signed, key)
    } yield verified

  HMACSHA512.generateKey[IO].flatMap(usingTypeclass[IO, HMACSHA512](toMac, _))

}
