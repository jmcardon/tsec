package tsec.common

abstract class ArrayNewt {
  type Type <: Array[Byte]

  final def apply(value: Array[Byte]): Type             = value.asInstanceOf[Type]
  final def subst[F[_]](value: F[Array[Byte]]): F[Type] = value.asInstanceOf[F[Type]]
}

private[tsec] abstract class ArrayHKNewt {
  type Type[A] <: Array[Byte]

  final def apply[A](value: Array[Byte]): Type[A] = value.asInstanceOf[Type[A]]
  final def subst[A]: ArrayHKNewtApplied[A, Type] = new ArrayHKNewtApplied[A, Type]

  final def unsubst[A]: ArrayHKNewtUnapplied[A, Type] = new ArrayHKNewtUnapplied[A, Type]

}

private[tsec] final class ArrayHKNewtUnapplied[A, Type[B] <: Array[Byte]](val dummy: Boolean = true) extends AnyVal {
  def apply[F[_]](value: F[Type[A]]): F[Array[Byte]] = value.asInstanceOf[F[Array[Byte]]]
}

private[tsec] final class ArrayHKNewtApplied[A, Type[B] <: Array[Byte]](val dummy: Boolean = true) extends AnyVal {
  def apply[F[_]](value: F[Array[Byte]]): F[Type[A]] = value.asInstanceOf[F[Type[A]]]
}
