package fucc.cipher.instances.padding

import fucc.cipher.core.{CipherPadding, Padding}
import fucc.core.CryptoTag

abstract class WithPaddingTag[T](repr: String){
  implicit val tag: Padding[T] = CryptoTag.fromStringTagged[T, CipherPadding](repr)
}
