package x509scan;

import java.util.List;

import org.apache.commons.validator.routines.DomainValidator;
import org.apache.commons.validator.routines.InetAddressValidator;
import org.apache.commons.validator.routines.IntegerValidator;

public class Validator {

  private final ICLIOptions cliOptions;
  private boolean valid;

  public Validator(ICLIOptions cliOptions) {
    this.cliOptions = cliOptions;
  }

  public void validate() {
    try {
      List<String> ipAddressList = this.cliOptions.getIpAddressList();
      validateIPAddressList(ipAddressList);
      List<String> portList = this.cliOptions.getPorts();
      validatePortList(portList);
      valid = true;
    } catch (IllegalArgumentException e) {
      System.out.println(e.getMessage());
    }
  }

  private void validateIPAddressList(List<String> ipAddressList) throws IllegalArgumentException {
    InetAddressValidator inetAddressValidator = InetAddressValidator.getInstance();
    DomainValidator domainValidator = DomainValidator.getInstance();
    for (String inetAddress : ipAddressList) {
      boolean validInetAddress = inetAddressValidator.isValid(inetAddress);
      boolean validDomain = false;
      if (!validInetAddress) {
        validDomain = domainValidator.isValid(inetAddress);
      }
      if (!validInetAddress && !validDomain) {
        throw new IllegalArgumentException("Invalid host address: " + inetAddress);
      }
    }
  }

  private void validatePortList(List<String> portList) throws IllegalArgumentException {
    IntegerValidator integerValidator = IntegerValidator.getInstance();
    for (String port : portList) {
      if (!integerValidator.isValid(port)) {
        throw new IllegalArgumentException("Invalid port: " + port);
      }
      Integer i = Integer.valueOf(port);
      if (!integerValidator.isInRange(i, 1, 65535)) {
        throw new IllegalArgumentException("Specified port value " + port + " outside of valid port range [1-65535].");
      }
    }
  }
}
