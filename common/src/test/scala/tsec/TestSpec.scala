package tsec

import org.scalatest.{FlatSpec, MustMatchers}
import org.scalatest.prop.PropertyChecks

trait TestSpec extends FlatSpec with MustMatchers with PropertyChecks
