package tsec.hashing.bouncy

import cats.Id
import tsec.Bouncy
import tsec.hashing._

protected[bouncy] abstract class AsBouncyCryptoHash[H](repr: String) extends BouncyDigestTag[H] with CryptoHashAPI[H] {

  /** Get our instance of jca crypto hash **/
  def hashPure(s: Array[Byte])(implicit C: CryptoHasher[Id, H], B: Bouncy): CryptoHash[H] = C.hash(s)

  def algorithm: String = repr

  implicit val tag: BouncyDigestTag[H] = this

}
