package x509scan;

public class CLIOptionsContextFactory {

  public ICLIOptionsContext createContext() {
    return new DefaultCLIOptionsContext();
  }

}
