package tsec.hashing

import fs2.Pipe

trait CryptoHasher[F[_], A] {

  /** Lift a the cryptographic hash function into an
    * F[_]
    *
    * The underlying hash function may or may not side effect.
    * @return
    */
  def hash(bytes: Array[Byte]): F[CryptoHash[A]]

  /** A pipe that transforms a byte stream into the stream of its
    * cryptographic hash.
    *
    * Useful for hashes of arbitrary length.
    */
  def hashPipe: Pipe[F, Byte, Byte]

}
