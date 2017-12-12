object MacExamples {

  /** Example message authentication: Note, will use byteutils */
  import tsec.common._
  import tsec.mac.imports._


  val toMac: Array[Byte] = "hi!".utf8Bytes

  val `mac'd`: Either[Throwable, Boolean] = for {
    key       <- HMACSHA256.generateKey()                        //Generate our key.
    macValue  <- JCAMacImpure.sign(toMac, key)                   //Generate our MAC bytes
    verified  <- JCAMacImpure.verify(toMac, macValue, key)       //Verify a byte array with a signed, typed instance
    verified2 <- JCAMacImpure.verifyArrays(toMac, macValue, key) //Alternatively, use arrays directly
  } yield verified

  import cats.syntax.all._
  import cats.effect.Sync

  /** For Interpretation into any F */
  def `mac'd-pure`[F[_]: Sync]: F[Boolean] =
    for {
      key       <- HMACSHA256.generateLift[F]                //Generate our key.
      macValue  <- JCAMac.sign(toMac, key)                   //Generate our MAC bytes
      verified  <- JCAMac.verify(toMac, macValue, key)       //Verify a byte array with a signed, typed instance
      verified2 <- JCAMac.verifyArrays(toMac, macValue, key) //Alternatively, use arrays directly
    } yield verified

}
