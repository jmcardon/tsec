package tsec.mac.imports

import cats.effect.Sync
import tsec.mac.core.MAC

object JCAMac {

  @deprecated("Use [Algorithm].sign[F]", "0.0.1-M11")
  def sign[F[_]: Sync, A](content: Array[Byte], key: MacSigningKey[A])(
      implicit jc: JCAMessageAuth[F, A]
  ): F[MAC[A]] = jc.sign(content, key)

  @deprecated("Use [Algorithm].verify[F]", "0.0.1-M11")
  def verify[F[_]: Sync, A](toSign: Array[Byte], signed: MAC[A], key: MacSigningKey[A])(
      implicit jc: JCAMessageAuth[F, A]
  ): F[Boolean] = jc.verify(toSign, signed, key)

  @deprecated("Use [Algorithm].verify[F]", "0.0.1-M11")
  def verifyArrays[F[_]: Sync, A](toSign: Array[Byte], signed: Array[Byte], key: MacSigningKey[A])(
      implicit jc: JCAMessageAuth[F, A]
  ): F[Boolean] = jc.verify(toSign, MAC[A](signed), key)
}

object JCAMacImpure {
  @deprecated("Use [Algorithm].verify[MacErrorM]", "0.0.1-M11")
  def sign[A](content: Array[Byte], key: MacSigningKey[A])(
      implicit jc: JCAMessageAuth[MacErrorM, A]
  ): MacErrorM[MAC[A]] = jc.sign(content, key)

  @deprecated("Use [Algorithm].verify[MacErrorM]", "0.0.1-M11")
  def verify[A](toSign: Array[Byte], signed: MAC[A], key: MacSigningKey[A])(
      implicit jc: JCAMessageAuth[MacErrorM, A]
  ): MacErrorM[Boolean] = jc.verify(toSign, signed, key)

  @deprecated("Use [Algorithm].verify[MacErrorM]", "0.0.1-M11")
  def verifyArrays[A](toSign: Array[Byte], signed: Array[Byte], key: MacSigningKey[A])(
      implicit jc: JCAMessageAuth[MacErrorM, A]
  ): MacErrorM[Boolean] = jc.verify(toSign, MAC[A](signed), key)
}
