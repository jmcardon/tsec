package tsec.cipher.instances.mode

sealed trait NoMode
object NoMode extends WithModeTag[NoMode]("NONE") with DefaultModeKeySpec[NoMode]
