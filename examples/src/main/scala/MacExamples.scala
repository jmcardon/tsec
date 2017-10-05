object MacExamples {

  import tsec.mac.imports._

  /** Example message authentication: Note, will use byteutils */
  import tsec.common._

  val macInstance: JCAMacImpure[HMACSHA256] = JCAMacImpure[HMACSHA256]
  val toMac: Array[Byte]                    = "hi!".utf8Bytes
  val `mac'd`: Either[Throwable, Boolean] = for {
    key       <- HMACSHA256.generateKey() //Generate our key.
    macValue  <- macInstance.sign(toMac, key) //Generate our MAC bytes
    verified  <- macInstance.verify(toMac, macValue, key) //Verify a byte array with a signed, typed instance
    verified2 <- macInstance.verifyArrays(toMac, macValue, key) //Alternatively, use arrays directly
  } yield verified

}
