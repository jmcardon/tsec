package fucc.cipher

import fucc.core.CryptoTag


abstract class Algorithm[T](repr: String){
  implicit val tag = CryptoTag.fromString[T](repr)
}

trait DES
object DES extends Algorithm[DES]("DES")