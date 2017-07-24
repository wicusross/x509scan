package x509scan;

import java.io.ByteArrayOutputStream;

public class ProcessMessage implements IMessage {

  private final String host;
  private final int port;
  private final ByteArrayOutputStream out;
  private byte[] data;
  private String cName;

  public ProcessMessage(String host, int port, ByteArrayOutputStream out) {
    this.host = host;
    this.port = port;
    this.out = out;
  }

  @Override
  public MessageType getMessageType() {
    return MessageType.PROCESS;
  }

  public String getHost() {
    return host;
  }

  public int getPort() {
    return port;
  }

  public ByteArrayOutputStream getOut() {
    return out;
  }

  public void setData(byte[] data) {
    this.data = data;
  }

  public byte[] getData() {
    return data;
  }

  public void setCName(String cName) {
    this.cName = cName;
  }

  public String getCName() {
    return this.cName;
  }

}
