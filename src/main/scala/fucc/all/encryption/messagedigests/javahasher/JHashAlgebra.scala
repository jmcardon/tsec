package fucc.all.encryption.messagedigests.javahasher

import cats.Monoid
import fucc.all.encryption.messagedigests.core._

class JHashAlgebra[T: HashTag](implicit hasher: PureHasher[T]) extends HashAlgebra[T] {
  type S = DigestLift

  implicit def monoid: Monoid[DigestLift] = new Monoid[DigestLift]{
    override def empty: DigestLift = DigestLift(Nil)

    override def combine(x: DigestLift, y: DigestLift): DigestLift = y.copy(list = x.list:::y.list)
  }

  override def liftS(s: Array[Byte]): DigestLift = DigestLift(s.toList)

  override def hash(s: Array[Byte]): Array[Byte] = hasher.hashToBytes(s)

  override def consume(state: DigestLift): Array[Byte] = hasher.hashToBytes(state.list.toArray)
}
