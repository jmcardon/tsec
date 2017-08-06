package fucc.passwordhashers

import fucc.passwordhashers.core._

package object syntax {

  implicit class Hasher(val password: String) extends AnyVal {

    def hash[T](implicit passwordHasher: PWHashPrograms[PasswordValidated,T]): PasswordValidated[T] = {
      passwordHasher.hash(password)
    }

    def check[T](hash: T)(implicit passwordHasher: PWHashPrograms[PasswordValidated,T]): PasswordValidated[Boolean] = {
      passwordHasher.checkHashed(password, hash)
    }
  }

}
