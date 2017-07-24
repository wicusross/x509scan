package x509scan;

import java.io.IOException;

public class StdOutputMethod implements OutputMethod {

  @Override
  public void writeOutput(String host, int port, byte[] data, String cname) throws IOException {
    if (data != null && data.length > 0) {
      String s = new String(data);
      System.out.println("Begin Certificates for host: " + host);
      System.out.println("Begin Certificates for CN: " + cname);
      System.out.println(s);
      System.out.println("End Certificates for host: " + host);
    }
  }

}
