package x509scan;

public enum OutputType {

  STDOUT, FILE;

  static OutputType parse(String value) {
    OutputType result = null;
    if (value != null && "STDOUT".equalsIgnoreCase(value)) {
      result = STDOUT;
    } else if (value != null && "FILE".equalsIgnoreCase(value)) {
      result = FILE;
    }
    return result;
  }

}
