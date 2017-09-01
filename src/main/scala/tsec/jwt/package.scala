package tsec

import java.nio.charset.StandardCharsets

import io.circe.Printer

package object jwt {
  val JWTPrinter = Printer(preserveOrder = true, dropNullValues = true,"")
}