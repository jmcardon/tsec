package tsec

import tsec.common.TSecError

import scala.reflect.ClassTag

package object authorization {

  type AuthGroup[G] = AuthGroup.Type[G]
  
  object AuthGroup {
    type Type[A] <: Array[A]

    private def unsafeApply[G: ClassTag](array: Array[G]) = array.asInstanceOf[AuthGroup[G]]

    def apply[G: ClassTag](values: G*): AuthGroup[G]    = values.toSet.toArray.asInstanceOf[AuthGroup[G]]
    def fromSet[G: ClassTag](set: Set[G]): AuthGroup[G] = set.toArray.asInstanceOf[AuthGroup[G]]
    def unsafeFromArray[G: ClassTag](array: Array[G]): AuthGroup[G] = {
      val arrayLen = array.length
      val newArr   = new Array[G](arrayLen)
      System.arraycopy(array, 0, newArr, 0, arrayLen)
      newArr.asInstanceOf[AuthGroup[G]]
    }
    def fromSeq[G: ClassTag](seq: Seq[G]): AuthGroup[G]       = unsafeApply[G](seq.distinct.toArray)
    def unsafeFromSeq[G: ClassTag](seq: Seq[G]): AuthGroup[G] = unsafeApply(seq.toArray)
    def empty[G: ClassTag]: AuthGroup[G]           = unsafeApply[G](Array.empty[G])
  }

  /** A simple typeclass that allows us to propagate information that is required for authorization */
  trait AuthorizationInfo[F[_], Role, U] {
    def fetchInfo(u: U): F[Role]
  }

  trait DynamicAuthGroup[F[_], Grp] {
    def fetchGroupInfo: F[AuthGroup[Grp]]
  }

  type InvalidAuthLevel = InvalidAuthLevelError.type

  object InvalidAuthLevelError extends TSecError {
    val cause: String = "The minimum auth level is zero."
  }

}
