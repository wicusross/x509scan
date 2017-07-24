package x509scan;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.LinkedBlockingQueue;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class X509Worker implements Runnable {

  private static Log _log = LogFactory.getLog("x509scan.X509Worker");

  private final String name;
  private final LinkedBlockingQueue<IMessage> readMessageQueue;
  private final LinkedBlockingQueue<IMessage> writeMessageQueue;
  private boolean stop;

  public X509Worker(String name, LinkedBlockingQueue<IMessage> readMessageQueue, LinkedBlockingQueue<IMessage> writeMessageQueue) {
    this.name = name;
    this.readMessageQueue = readMessageQueue;
    this.writeMessageQueue = writeMessageQueue;
    this.stop = false;
  }

  @Override
  public void run() {
    X509Worker._log.debug("Starting " + name);
    while (!stop) {
      IMessage message = null;
      try {
        message = readMessageQueue.take();
      } catch (InterruptedException e) {
        e.printStackTrace();
      }
      if (message != null) {
        handleMessage(message);
      }
    }
    X509Worker._log.debug("Exiting " + name);
  }

  private void handleMessage(IMessage message) {
    IMessage.MessageType messageType = message.getMessageType();
    X509Worker._log.debug("Received message " + messageType);
    if (messageType != null && IMessage.MessageType.PROCESS.equals(messageType)) {
      processMessage((ProcessMessage) message);
    } else if (messageType != null && IMessage.MessageType.STOP.equals(messageType)) {
      this.stop = true;
      X509Worker._log.debug("Writing stop message");
      writeMessageQueue.offer(message);
    } else {
      System.err.println("Unsupported message type: " + messageType);
    }
  }

  private void processMessage(ProcessMessage processMessage) {
    ByteArrayOutputStream baos = processMessage.getOut();
    PrintStream out = new PrintStream(processMessage.getOut());
    String host = processMessage.getHost();
    int port = processMessage.getPort();
    X509Worker._log.debug("Going to scan host " + host + " on port " + port);
    SSLClient sslClient = new SSLClient(out);
    String cName = null;
    try {
      sslClient.connect(host, port);
      cName = sslClient.getCName();
    } catch (KeyManagementException e) {
      X509Worker._log.error(e);
    } catch (NoSuchAlgorithmException e) {
      X509Worker._log.error(e);
    }
    out.flush();
    out.close();
    X509Worker._log.debug("Finished scanning host " + host + " on port " + port);
    byte[] data = baos.toByteArray();
    processMessage.setData(data);
    processMessage.setCName(cName);
    X509Worker._log.debug("Sending result back");
    writeMessageQueue.offer(processMessage);
  }

}
