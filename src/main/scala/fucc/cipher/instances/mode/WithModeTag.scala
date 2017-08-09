package fucc.cipher.instances.mode

import fucc.cipher.core.{CipherMode, CMode}
import fucc.core.CryptoTag

abstract class WithModeTag[T](repr: String){
  implicit val tag: CMode[T] = CryptoTag.fromStringTagged[T, CipherMode](repr)
}
