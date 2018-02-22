package tsec.hashing.core

import cats.effect.Sync
import fs2.Pipe

trait CryptoHashAlgebra[A, S] {

  /** The cryptographic hash function, in its
    * raw form
    *
    * It may or may not be pure, depending on the implementation of
    * S (in libsodium it is not pure, since JNI,
    * but in java it is essentially pure)
    *
    * @return
    */
  def unsafeHash(bytes: Array[Byte])(implicit S: S): CryptoHash[A]

  /** Lift a the cryptographic hash function into an
    * F[_] which captures side effects.
    *
    * The underlying hash function may or may not side effect.
    * @return
    */
  def hashF[F[_]](bytes: Array[Byte])(implicit F: Sync[F], S: S): F[CryptoHash[A]]

  /** A pipe that transforms a byte stream into the stream of its
    * cryptographic hash.
    *
    * Useful for hashes of arbitrary length.
    */
  def hashPipe[F[_]](implicit F: Sync[F], S: S): Pipe[F, Byte, Byte]

}
