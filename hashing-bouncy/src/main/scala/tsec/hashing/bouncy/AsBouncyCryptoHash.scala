package tsec.hashing.bouncy

import cats.{Applicative, Id}
import tsec.Bouncy
import tsec.hashing._

protected[bouncy] abstract class AsBouncyCryptoHash[H](repr: String) extends CryptoHashAPI[H] {

  /** Get our instance of jca crypto hash **/
  def hashPure(s: Array[Byte])(implicit C: CryptoHasher[Id, H]): CryptoHash[H] = C.hash(s)

  implicit def genHasher[F[_]: Applicative, A](implicit B: Bouncy): CryptoHasher[F, A] =
    new BouncyHasher[F, A](repr)

}
