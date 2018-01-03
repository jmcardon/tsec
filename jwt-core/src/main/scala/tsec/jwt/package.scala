package tsec

import io.circe.Printer

package object jwt {
  val JWTPrinter = Printer(preserveOrder = true, dropNullValues = true, "")
}
