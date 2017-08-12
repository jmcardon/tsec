package tsec.passwordhashers

import tsec.passwordhashers.core._

package object syntax {

  implicit class Hasher(val password: String) extends AnyVal {

    def hashPassword[T](implicit passwordHasher: PWHashPrograms[PasswordValidated, T]): PasswordValidated[T] =
      passwordHasher.hash(password)

    def checkWithHash[T](
        hash: T
    )(implicit passwordHasher: PWHashPrograms[PasswordValidated, T]): PasswordValidated[Boolean] =
      passwordHasher.checkHashed(password, hash)
  }
}
