package fucc.all.encryption.passwordhashers.defaults

import fucc.all.encryption.passwordhashers.core._

package object ops {

  implicit class Hasher(val password: String) extends AnyVal {

    def hash[T](implicit passwordHasher: PWHashPrograms[PasswordValidated,T]): PasswordValidated[T] = {
      passwordHasher.hash(Password(password))
    }

    def check[T](hash: T)(implicit passwordHasher: PWHashPrograms[PasswordValidated,T]): PasswordValidated[Boolean] = {
      passwordHasher.checkHashed(Password(password),hash)
    }

  }

}
