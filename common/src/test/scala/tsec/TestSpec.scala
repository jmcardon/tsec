package tsec

import org.scalatest.MustMatchers
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatestplus.scalacheck.ScalaCheckPropertyChecks

trait TestSpec extends AnyFlatSpec with MustMatchers with ScalaCheckPropertyChecks
