package tsec.signature.instance

import java.security.spec.ECGenParameterSpec

trait ECCurve[A] {
  protected val defaultCurve: String
  def keySpecFromCurve: ECGenParameterSpec = new ECGenParameterSpec(defaultCurve)
}
