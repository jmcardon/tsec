package tsec.messagedigests.imports

import java.security.MessageDigest
import tsec.messagedigests.core._

/** Intepreter for the java default security implementation
  * @tparam T
  */
class JHashAlgebra[T](implicit tag: DigestTag[T]) extends HashAlgebra[T] {
  type H = MessageDigest

  def genInstance(): MessageDigest = MessageDigest.getInstance(tag.algorithm)

  def hash(s: Array[Byte]): Array[Byte] = genInstance().digest(s)
}
