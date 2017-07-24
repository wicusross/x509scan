package x509scan;

import java.io.IOException;
import java.io.PrintStream;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.Base64;
import java.util.Base64.Encoder;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.cert.CertificateEncodingException;
import javax.security.cert.X509Certificate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class SSLClient {

  private String subjectName;
  private String cName;
  private static Log _log = LogFactory.getLog("x509scan.SSLClient");

  private static TrustManager[] trustAllCerts = new TrustManager[] {new X509TrustManager() {

    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
      return null;
    }

    public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
    }

    public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
    }
  }};

  private final PrintStream out;

  public SSLClient(PrintStream out) {
    this.out = out;
  }

  public void connect(String host, int port) throws NoSuchAlgorithmException, KeyManagementException {
    SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
    sslContext.init(null, SSLClient.trustAllCerts, new java.security.SecureRandom());
    SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
    SSLSocket sslSocket = null;
    try {
      sslSocket = (SSLSocket) sslSocketFactory.createSocket(host, port);
      SSLScanHandshakeCompletedListener handshakelistner = new SSLScanHandshakeCompletedListener(host, port);
      sslSocket.addHandshakeCompletedListener(handshakelistner);
      sslSocket.startHandshake();
      SSLClient._log.debug("");
      handshakelistner.waitForHandshakeCompletion(30 * 1000); // Thirty Seconds
      printSocketInfo(sslSocket);
    } catch (IOException e) {
      SSLClient._log.error("Unable to open connection to host: " + host + " on port " + port + ". Reason: " + e.getMessage());
    } finally {
      if (sslSocket != null) {
        try {
          sslSocket.close();
        } catch (IOException e) {
        }
      }
    }
  }

  private void printSocketInfo(SSLSocket s) {
    SSLClient._log.debug(" Remote address = " + s.getInetAddress().toString());
    SSLClient._log.debug(" Remote address = " + s.getInetAddress().toString());
    SSLClient._log.debug(" Remote port = " + s.getPort());
    SSLClient._log.debug(" Local socket address = " + s.getLocalSocketAddress().toString());
    SSLClient._log.debug(" Local address = " + s.getLocalAddress().toString());
    SSLClient._log.debug(" Local port = " + s.getLocalPort());
    SSLClient._log.debug(" Need client authentication = " + s.getNeedClientAuth());
    SSLSession ss = s.getSession();
    SSLClient._log.debug(" Cipher suite = " + ss.getCipherSuite());
    SSLClient._log.debug(" Protocol = " + ss.getProtocol());
    X509Certificate[] x509Certs = null;
    try {
      x509Certs = ss.getPeerCertificateChain();
      dumpX509Certs(x509Certs);
    } catch (SSLPeerUnverifiedException e) {
      SSLClient._log.error(e);
    }
  }

  private void dumpX509Certs(X509Certificate[] x509Certs) {
    StringBuilder sb = new StringBuilder();
    for (X509Certificate cert : x509Certs) {
      if (sb.length() > 0) {
        sb.append("\n");
      }
      sb.append("-----BEGIN CERTIFICATE-----\n");
      if (subjectName == null) {
        Principal subject = cert.getSubjectDN();
        subjectName = subject.getName();
      }
      Encoder encoder = Base64.getMimeEncoder();
      try {
        sb.append(encoder.encodeToString(cert.getEncoded()));
      } catch (CertificateEncodingException e) {
        SSLClient._log.error(e);
      }
      sb.append("\n-----END  CERTIFICATE-----");
    }
    extractCName();
    if (sb.length() > 0) {
      this.out.print(sb.toString());
    }

  }

  /**
   *
   * Copied from https://stackoverflow.com/questions/2914521/how-to-extract-cn-from-x509certificate-in-java
   *
   * Warning edge case for RFC-2253.
   *
   * Formatting could fail.
   *
   * @param dn
   * @param attributeType
   * @return
   */
  private String getValByAttributeTypeFromIssuerDN(String dn, String attributeType) {
    String[] dnSplits = dn.split(",");
    for (String dnSplit : dnSplits) {
      if (dnSplit.contains(attributeType)) {
        String[] cnSplits = dnSplit.trim().split("=");
        if (cnSplits[1] != null) {
          return cnSplits[1].trim();
        }
      }
    }
    return "";
  }

  private void extractCName() {
    if (subjectName != null) {
      cName = getValByAttributeTypeFromIssuerDN(subjectName, "CN=");
    }
  }

  public String getCName() {
    return cName;
  }
}
