package x509scan;

public class StopMessage implements IMessage {

  @Override
  public MessageType getMessageType() {
    return MessageType.STOP;
  }

}
