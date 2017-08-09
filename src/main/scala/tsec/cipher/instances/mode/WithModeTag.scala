package tsec.cipher.instances.mode

import tsec.cipher.core.{CipherMode, CMode}
import tsec.core.CryptoTag

abstract class WithModeTag[T](repr: String){
  implicit val tag: CMode[T] = CryptoTag.fromStringTagged[T, CipherMode](repr)
}
