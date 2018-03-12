package tsec.passwordhashers.imports

import cats.effect.Sync
import tsec.passwordhashers.core._

trait JCAPasswordPlatform[A] extends PasswordHashAPI[A] {

  private[tsec] def unsafeHashpw(p: Array[Byte]): String

  private[tsec] def unsafeCheckpw(p: Array[Byte], hash: PasswordHash[A]): Boolean

  implicit val idPasswordHasher: IdPasswordHasher[A] = new IdPasswordHasher[A] {
    private[tsec] def checkPassUnsafe(p: Array[Byte], hash: PasswordHash[A]) = unsafeCheckpw(p, hash)

    private[tsec] def hashPassUnsafe(p: Array[Byte]) = unsafeHashpw(p)
  }

  implicit def syncPasswordHasher[F[_]](implicit F: Sync[F]): PasswordHasher[F, A] =
    new PasswordHasher[F, A] {
      def hashpw(p: Array[Char]): F[PasswordHash[A]] = F.delay(hashpwUnsafe(p))

      def hashpw(p: Array[Byte]): F[PasswordHash[A]] = F.delay(hashpwUnsafe(p))

      def checkpw(p: Array[Char], hash: PasswordHash[A]): F[Boolean] =
        F.delay(checkpwUnsafe(p, hash))

      def checkpw(p: Array[Byte], hash: PasswordHash[A]): F[Boolean] =
        F.delay(checkpwUnsafe(p, hash))

      private[tsec] def hashPassUnsafe(p: Array[Byte]): String = unsafeHashpw(p)

      private[tsec] def checkPassUnsafe(p: Array[Byte], hash: PasswordHash[A]): Boolean = unsafeCheckpw(p, hash)
    }

}
