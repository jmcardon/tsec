package tsec.kdf

package object libsodium {

  //Todo: Good application for refined
  type MasterKey = MasterKey.Type

  //Todo: Check keyLen for building.
  object MasterKey {
    type Type <: Array[Byte]

    def apply(value: Array[Byte]): MasterKey             = value.asInstanceOf[MasterKey]
    def subst[F[_]](value: F[Array[Byte]]): F[MasterKey] = value.asInstanceOf[F[MasterKey]]

    def unsubst[F[_]](value: F[MasterKey]): F[Array[Byte]] = value.asInstanceOf[F[Array[Byte]]]

  }

  //Todo: Good application for refined
  type DerivedKey = DerivedKey.Type

  //Todo: Check keyLen for building.
  object DerivedKey {
    type Type <: Array[Byte]

    def apply(value: Array[Byte]): DerivedKey             = value.asInstanceOf[DerivedKey]
    def subst[F[_]](value: F[Array[Byte]]): F[DerivedKey] = value.asInstanceOf[F[DerivedKey]]
    def unsubst[F[_]](value: F[DerivedKey]): F[Array[Byte]] = value.asInstanceOf[F[Array[Byte]]]
  }

}
