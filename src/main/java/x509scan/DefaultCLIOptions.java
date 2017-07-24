package x509scan;

import java.util.List;

public class DefaultCLIOptions implements ICLIOptions {

  private String outputFilePath;
  private List<String> ipAddressList;
  private List<String> portList;
  private OutputType outputType;
  private int maxWorkerThreadPoolSize = 10;

  void setIpAddressList(List<String> ipAddressList) {
    this.ipAddressList = ipAddressList;
  }

  @Override
  public List<String> getIpAddressList() {
    return ipAddressList;
  }

  void setPortList(List<String> portList) {
    this.portList = portList;
  }

  @Override
  public List<String> getPorts() {
    return portList;
  }

  void setOutputType(OutputType outputType) {
    this.outputType = outputType;
  }

  @Override
  public OutputType getOutputType() {
    return outputType;
  }

  void setMaxWorkerThreadPoolSize(int maxWorkerThreadPoolSize) {
    this.maxWorkerThreadPoolSize = maxWorkerThreadPoolSize;
  }

  @Override
  public int getMaxWorkerThreadPoolSize() {
    return this.maxWorkerThreadPoolSize;
  }

  public String getOutputFilePath() {
    return this.outputFilePath;
  }

  void setOutputFilePath(String outputFilePath) {
    this.outputFilePath = outputFilePath;
  }

}
