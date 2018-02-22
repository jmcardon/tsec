package tsec.hashing.core

import fs2.Pipe

trait CryptoHasher[F[_], A] {

  /** The cryptographic hash function, in its
    * raw form
    *
    * It may or may not be pure, depending on the implementation of
    * S (in libsodium it is not pure, since JNI,
    * but in java it is essentially pure)
    *
    * @return
    */
  def unsafeHash(bytes: Array[Byte]): CryptoHash[A]

  /** Lift a the cryptographic hash function into an
    * F[_] which captures side effects.
    *
    * The underlying hash function may or may not side effect.
    * @return
    */
  def hashF(bytes: Array[Byte]): F[CryptoHash[A]]

  /** A pipe that transforms a byte stream into the stream of its
    * cryptographic hash.
    *
    * Useful for hashes of arbitrary length.
    */
  def hashPipe: Pipe[F, Byte, Byte]

}
