import cats.effect.IO

object MacExamples {

  /** Example message authentication: Note, will use byteutils */
  import tsec.common._
  import tsec.mac.imports._

  type ET[PhoneHome] = Either[Throwable, PhoneHome]

  val toMac: Array[Byte] = "hi!".utf8Bytes

  val `mac'd`: Either[Throwable, Boolean] = for {
    key      <- HMACSHA256.generateKey()                    //Generate our key.
    macValue <- HMACSHA256.sign[ET](toMac, key)             //Generate our MAC bytes
    verified <- HMACSHA256.verify[ET](toMac, macValue, key) //Verify a byte array with a signed, typed instance
  } yield verified

  import cats.syntax.all._
  import cats.effect.Sync

  /** For Interpretation into any F */
  def `mac'd-pure`[F[_]: Sync]: F[Boolean] =
    for {
      key      <- HMACSHA256.generateLift[F]                 //Generate our key.
      macValue <- HMACSHA256.sign[F](toMac, key)             //Generate our MAC bytes
      verified <- HMACSHA256.verify[F](toMac, macValue, key) //Verify a byte array with a signed, typed instance
    } yield verified

  /** Using the typeclass [[tsec.mac.core.MessageAuth]],
    * JCASigner is simply the class over java secret keys
    *
    */
  def usingTypeclass[F[_]: Sync, A](mToSign: Array[Byte], key: MacSigningKey[A])(
      implicit messageAuth: JCAMac[F, A]
  ): F[Boolean] =
    for {
      signed   <- messageAuth.sign(mToSign, key)
      verified <- messageAuth.verify(mToSign, signed, key)
    } yield verified

  HMACSHA512.generateLift[IO].flatMap(usingTypeclass[IO, HMACSHA512](toMac, _))

}
