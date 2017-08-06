import cats.Eq
import fucc.passwordhashers.core.PasswordError
import fucc.passwordhashers.instances.BCrypt
import org.scalatest.FlatSpec

trait TestSpec extends FlatSpec {

  implicit val PasswordErrorCatsEqInstance = new Eq[PasswordError] {
    override def eqv(x: PasswordError, y: PasswordError): Boolean =
      x.reason === y.reason
  }
  implicit val BCryptCatsEqInstance = new Eq[BCrypt] {
    override def eqv(x: BCrypt, y: BCrypt): Boolean = {
      x.hashed === y.hashed
    }
  }

}
