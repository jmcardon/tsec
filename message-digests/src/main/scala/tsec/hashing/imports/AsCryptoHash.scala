package tsec.hashing.imports

import java.security.MessageDigest

import cats.effect.Sync
import tsec.hashing.core._

protected[imports] abstract class AsCryptoHash[H](repr: String)
    extends JCADigestTag[H]
    with CryptoHashAlgebra[H, DummyImplicit] {

  /** Get our instance of jca crypto hash **/
  private def genInstance(): MessageDigest = MessageDigest.getInstance(tag.algorithm)

  def hash(s: Array[Byte]): CryptoHash[H] = CryptoHash[H](genInstance().digest(s))

  def algorithm: String = repr

  implicit val tag: JCADigestTag[H] = this

  def unsafeHash(bytes: Array[Byte])(implicit S: DummyImplicit): CryptoHash[H] =
    hash(bytes)

  def hashF[F[_]](bytes: Array[Byte])(implicit F: Sync[F], S: DummyImplicit): F[CryptoHash[H]] =
    F.pure(hash(bytes))

}
