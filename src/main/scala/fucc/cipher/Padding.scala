package fucc.cipher

import fucc.core.CryptoTag


abstract class Padding[T](repr: String){
  implicit val tag = CryptoTag.fromString[T](repr)
}

trait `PKCS5Padding`
object `PKCS5Padding` extends Padding[`PKCS5Padding`]("PKCS5Padding")