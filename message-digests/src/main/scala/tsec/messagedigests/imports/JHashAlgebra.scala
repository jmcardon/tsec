package tsec.messagedigests.imports

import java.security.MessageDigest

import cats.Monoid
import tsec.messagedigests.DigestLift
import tsec.messagedigests.core._

import scala.annotation.tailrec

/** Intepreter for the java default security implementation
  * @tparam T
  */
class JHashAlgebra[T](implicit tag: DigestTag[T]) extends HashAlgebra[T] {
  type S = DigestLift

  type H = MessageDigest

  def genInstance(): MessageDigest = MessageDigest.getInstance(tag.algorithm)

  implicit def monoid: Monoid[DigestLift] = new Monoid[DigestLift] {
    def empty: DigestLift = DigestLift(Nil)

    def combine(x: DigestLift, y: DigestLift): DigestLift =
      y.copy(list = x.list ::: y.list)
  }

  def liftS(s: Array[Byte]): DigestLift = DigestLift(List(s))

  def lift(s: List[Array[Byte]]): DigestLift = DigestLift(s)

  def hash(s: Array[Byte]): Array[Byte] = genInstance().digest(s)

  def consume(state: DigestLift): Array[Byte] = {
    @tailrec def impureConcat(concatArray: Array[Byte], indexList: List[Int], arrays: List[Array[Byte]]): Array[Byte] =
      indexList match {
        case Nil => concatArray
        case x :: xs =>
          arrays.head.copyToArray(concatArray, x)
          impureConcat(concatArray, xs, arrays.tail)
      }

    @tailrec def indexList(prev: Int, array: List[Array[Byte]], accum: List[Int]): List[Int] = array match {
      case Nil      => accum
      case _ :: Nil => accum
      case x :: xs =>
        val newPrev = prev + x.length
        indexList(newPrev, xs, newPrev :: accum)
    }

    val newArray              = new Array[Byte](state.list.foldLeft(0)(_ + _.length))
    val combined: Array[Byte] = impureConcat(newArray, indexList(0, state.list, List(0)).reverse, state.list)

    genInstance().digest(combined)
  }

  def hashBatch(state: DigestLift): List[Array[Byte]] = {
    val cached = genInstance()
    state.list.map(cached.digest)
  }
}
