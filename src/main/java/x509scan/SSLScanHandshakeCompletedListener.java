package x509scan;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class SSLScanHandshakeCompletedListener implements HandshakeCompletedListener {

  private static Log _log = LogFactory.getLog("x509scan.SSLScanHandshakeCompletedListener");

  private final CountDownLatch handshakeCompleteLatch;
  private final String host;
  private final int port;

  public SSLScanHandshakeCompletedListener(String host, int port) {
    this.host = host;
    this.port = port;
    this.handshakeCompleteLatch = new CountDownLatch(1);
  }

  @Override
  public void handshakeCompleted(HandshakeCompletedEvent event) {
    this.handshakeCompleteLatch.countDown();
    SSLScanHandshakeCompletedListener._log.debug("Handshake completed for host " + host + " on port " + port);
  }

  public void waitForHandshakeCompletion(long to) {
    try {
      if (!this.handshakeCompleteLatch.await(to, TimeUnit.MILLISECONDS)) {
        SSLScanHandshakeCompletedListener._log.error("Handshake timedout for host " + host + " on port " + port);
      }
    } catch (InterruptedException e) {
      SSLScanHandshakeCompletedListener._log.error(e);
    }
  }

}
