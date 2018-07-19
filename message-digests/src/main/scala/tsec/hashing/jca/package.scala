package tsec.hashing

import cats.Id

package object jca {

  private[tsec] final class ArrayHashOps(val bytes: Array[Byte]) extends AnyVal {

    /** We are summoning an implicit for a particular A
      * using cats.Id here, given hashing in java is
      * pure
      */
    def hash[A](implicit C: CryptoHasher[Id, A]): CryptoHash[A] =
      C.hash(bytes)
  }

  implicit final def hashOps(value: Array[Byte]): ArrayHashOps = new ArrayHashOps(value)

}
