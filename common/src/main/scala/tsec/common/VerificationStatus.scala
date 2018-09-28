package tsec.common

sealed trait VerificationStatus extends Product with Serializable
case object Verified            extends VerificationStatus
case object VerificationFailed  extends VerificationStatus
