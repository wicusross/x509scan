package x509scan;

public interface ICLIOptionsContext {

  void initialize(String[] args);

  boolean isValid();

  ICLIOptions getCLIOptions();

  String getHelp();

}
