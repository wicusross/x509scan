package x509scan;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class FileOutputMethod implements OutputMethod {

  private static Log _log = LogFactory.getLog("x509scan.FileOutputMethod");
  private final String basepath;

  public FileOutputMethod(String basepath) {
    this.basepath = basepath;
  }

  @Override
  public void writeOutput(String host, int port, byte[] data, String cname) throws IOException {
    String absolutePath = this.basepath + File.separator + host + "_" + port;
    absolutePath = absolutePath.replaceAll("\\.", "_");
    absolutePath += ".cer";
    if (data == null || data.length == 0) {
      FileOutputMethod._log.info("There is no data to write for file " + absolutePath);
    } else {
      FileOutputMethod._log.debug("Attempting to create file: " + absolutePath);
      File f = new File(absolutePath);
      if (f.exists()) {
        FileOutputMethod._log.info("File " + absolutePath + " exists. Not overwriting the files");
      } else {
        FileOutputMethod._log.debug("Writing data file: " + absolutePath);
        FileOutputStream fos = null;
        try {
          fos = new FileOutputStream(f);
          fos.write(new String("CN=" + cname + "\n").getBytes());
          fos.write(data);
          fos.flush();
        } catch (IOException e) {
          FileOutputMethod._log.debug(e);
          throw e;
        } finally {
          if (fos != null) {
            FileOutputMethod._log.debug("Closing file: " + absolutePath);
            fos.close();
          }
        }
      }
    }
  }

}
