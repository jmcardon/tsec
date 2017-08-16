package tsec.cipher.common.mode

sealed trait NoMode
object NoMode extends DefaultModeKeySpec[NoMode]("NONE")
