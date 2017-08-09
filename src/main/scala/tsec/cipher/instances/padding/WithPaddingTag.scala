package tsec.cipher.instances.padding

import tsec.cipher.core.{CipherPadding, Padding}
import tsec.core.CryptoTag

abstract class WithPaddingTag[T](repr: String){
  implicit val tag: Padding[T] = CryptoTag.fromStringTagged[T, CipherPadding](repr)
}
