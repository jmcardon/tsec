package tsec.cipher

import java.security.spec.AlgorithmParameterSpec

import com.softwaremill.tagging._

package object instances {
  type JSpec[T] = AlgorithmParameterSpec @@ T
  def tagSpec[T](a: AlgorithmParameterSpec): JSpec[T] = a.taggedWith[T]
}
