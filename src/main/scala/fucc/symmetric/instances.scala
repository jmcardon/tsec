package fucc.symmetric

object instances {

  implicit val AESInstance = JKeyGenerator.fromType[AES]
  implicit val DESInstance = JKeyGenerator.fromType[DES]

}
