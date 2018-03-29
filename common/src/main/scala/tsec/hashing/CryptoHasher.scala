package tsec.hashing

import java.security.MessageDigest

import cats.Functor
import fs2.Pipe
import tsec.common.{VerificationFailed, VerificationStatus, Verified}

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

  /** Check against another hash
    *
    */
  def checkWithHashBool(l: Array[Byte], r: CryptoHash[A])(implicit F: Functor[F]): F[Boolean] =
    F.map(hash(l))(MessageDigest.isEqual(_, r))

  /** Check against another hash
    *
    */
  def checkWithHash(l: Array[Byte], r: CryptoHash[A])(implicit F: Functor[F]): F[VerificationStatus] =
    F.map(hash(l))(c => if (MessageDigest.isEqual(c, r)) Verified else VerificationFailed)

}
