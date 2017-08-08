package fucc.symmetric

import fucc.core.CryptoTag

abstract class KeyGenAlgorithm[T](repr: String){
  implicit val tag = CryptoTag.fromString[T](repr)
}

trait AES
object AES extends KeyGenAlgorithm[AES]("AES")

trait DES
object DES extends KeyGenAlgorithm[DES]("DES")