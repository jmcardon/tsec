package tsec.passwordhashers

import tsec.common.TSecError

package object core {


  final case class PasswordError(cause: String) extends TSecError
}
