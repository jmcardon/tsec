package fucc.cipher

import fucc.core.CryptoTag

abstract class Mode[T](repr: String){
  implicit val tag = CryptoTag.fromString[T](repr)
}

trait CBC
object CBC extends Mode[CBC]("CBC")


trait ECB
object ECB extends Mode[ECB]("ECB")