package tsec.core

import shapeless.{::, Generic, HNil}

object ErrorConstruct {
  type ErrAux[A] = Generic[A] {
    type Repr = String :: HNil
  }

  def fromThrowable[A](e: Throwable)(implicit aux: ErrAux[A]): A = aux.from(e.getMessage :: HNil)
}
