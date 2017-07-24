package x509scan;

import java.util.List;

public interface ICLIOptions {

  List<String> getIpAddressList();

  List<String> getPorts();

  OutputType getOutputType();

  int getMaxWorkerThreadPoolSize();

  String getOutputFilePath();

}
