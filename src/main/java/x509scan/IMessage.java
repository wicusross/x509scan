package x509scan;

public interface IMessage {

  enum MessageType {
    PROCESS, STOP
  }

  MessageType getMessageType();

}
