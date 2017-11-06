object MacExamples {

  /** Example message authentication: Note, will use byteutils */
  import tsec.common._
  import tsec.mac.imports._

  val macInstance: JCAMacImpure[HMACSHA256] = JCAMacImpure[HMACSHA256]
  val toMac: Array[Byte]                    = "hi!".utf8Bytes
  val `mac'd`: Either[Throwable, Boolean] = for {
    key       <- HMACSHA256.generateKey()                       //Generate our key.
    macValue  <- macInstance.sign(toMac, key)                   //Generate our MAC bytes
    verified  <- macInstance.verify(toMac, macValue, key)       //Verify a byte array with a signed, typed instance
    verified2 <- macInstance.verifyArrays(toMac, macValue, key) //Alternatively, use arrays directly
  } yield verified

  import cats.effect.IO

  /** For Interpetation into IO */
  val macPureInstance: JCAMacPure[IO, HMACSHA256] = JCAMacPure[IO, HMACSHA256]
  val `mac'd-pure`: IO[Boolean] = for {
    key       <- HMACSHA256.generateLift[IO]                        //Generate our key.
    macValue  <- macPureInstance.sign(toMac, key)                   //Generate our MAC bytes
    verified  <- macPureInstance.verify(toMac, macValue, key)       //Verify a byte array with a signed, typed instance
    verified2 <- macPureInstance.verifyArrays(toMac, macValue, key) //Alternatively, use arrays directly
  } yield verified

}
