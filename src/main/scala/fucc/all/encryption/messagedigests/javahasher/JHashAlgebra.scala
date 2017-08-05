package fucc.all.encryption.messagedigests.javahasher

import java.security.MessageDigest

import cats.Monoid
import fucc.all.encryption.messagedigests.core._

class JHashAlgebra[T: HashTag](implicit hasher: PureHasher[MessageDigest,T]) extends HashAlgebra[T] {
  type S = DigestLift

  implicit def monoid: Monoid[DigestLift] = new Monoid[DigestLift]{
     def empty: DigestLift = DigestLift(Nil)

     def combine(x: DigestLift, y: DigestLift): DigestLift = y.copy(list = x.list:::y.list)
  }

   def liftS(s: Array[Byte]): DigestLift = DigestLift(s.toList)

   def hash(s: Array[Byte]): Array[Byte] = hasher.hashToBytes(s)

   def consume(state: DigestLift): Array[Byte] = hasher.hashToBytes(state.list.toArray)
}
