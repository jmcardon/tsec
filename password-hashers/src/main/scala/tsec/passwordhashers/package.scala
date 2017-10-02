package tsec

import tsec.passwordhashers.core._
package object passwordhashers {

  implicit class HasherSyntax(val password: String) extends AnyVal {

    def hashPassword[T](implicit passwordHasher: PWHashPrograms[PasswordValidated, T]): T =
      passwordHasher.hash(password)

    def hashPasswordUnsafe[T](
        rounds: Int
    )(implicit passwordHasher: PWHashPrograms[PasswordValidated, T]): PasswordValidated[T] =
      passwordHasher.hassPassUnsafe(password, Rounds(rounds))

    def checkWithHash[T](
        hash: T
    )(implicit passwordHasher: PWHashPrograms[PasswordValidated, T]): Boolean =
      passwordHasher.checkHashed(password, hash)
  }

}
