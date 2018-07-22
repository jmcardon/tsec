package tsec.hashing.jca

import cats.{Applicative, Id}
import tsec.hashing.{CryptoHashAPI, CryptoHasher, _}

protected[jca] abstract class AsCryptoHash[H](repr: String) extends CryptoHashAPI[H] {

  /** Get our instance of jca crypto hash **/
  def hashPure(s: Array[Byte])(implicit C: CryptoHasher[Id, H]): CryptoHash[H] = C.hash(s)

  implicit def jhasher[F[_]: Applicative]: JHasher[F, H] =
    new JHasher[F, H](repr)
}
