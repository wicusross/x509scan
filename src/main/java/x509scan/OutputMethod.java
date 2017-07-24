package x509scan;

import java.io.IOException;

public interface OutputMethod {

  void writeOutput(String host, int port, byte[] data, String cname) throws IOException;

}
