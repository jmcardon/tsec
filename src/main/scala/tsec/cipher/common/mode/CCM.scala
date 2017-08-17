package tsec.cipher.common.mode

/*
https://tools.ietf.org/html/rfc5084
IvLen of 12 octets is recommended
 */
sealed trait CCM
object CCM extends DefaultModeKeySpec[CCM]("CCM", 12)
