package tsec.cipher.common.padding

import tsec.cipher.common._
import tsec.core.CryptoTag

abstract class WithPaddingTag[T](repr: String) {
  implicit val tag: Padding[T] = CryptoTag.fromStringTagged[T, CipherPadding](repr)
}
