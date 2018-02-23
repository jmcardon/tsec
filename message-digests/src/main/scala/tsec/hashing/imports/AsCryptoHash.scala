package tsec.hashing.imports

import cats.Id
import tsec.hashing.core._

protected[imports] abstract class AsCryptoHash[H](repr: String) extends JCADigestTag[H] with CryptoHashAPI[H] {

  /** Get our instance of jca crypto hash **/
  def hash(s: Array[Byte]): CryptoHash[H] = implicitly[CryptoHasher[Id, H]].unsafeHash(s)

  def algorithm: String = repr

  implicit val tag: JCADigestTag[H] = this

}
