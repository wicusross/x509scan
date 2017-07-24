package x509scan;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

public class DefaultCLIOptionsContext implements ICLIOptionsContext {

  private static String APP_NAME = "x509scan";
  private static String OPTION_SHORT_HELP = "h";
  private static String OPTION_LONG_HELP = "help";
  private static String OPTION_HELP_DESCRIPTION = "print this message";
  private static String OPTION_SHORT_ADDRESS_LIST = "a";
  private static String OPTION_LONG_ADDRESS_LIST = "address-list";
  private static String OPTION_ADDRESS_LIST_DESCRIPTION = "the host address list, space separated";
  private static String OPTION_SHORT_PORT_LIST = "p";
  private static String OPTION_LONG_PORT_LIST = "port-list";
  private static String OPTION_PORT_LIST_DESCRIPTION = "the list of ports, space separated. Port 80 and 443 is implied if this option is not specified.";
  private static String OPTION_SHORT_OUTPUT_LIST = "o";
  private static String OPTION_LONG_OUTPUT_LIST = "output";
  private static String OPTION_OUTPUT_DESCRIPTION = "the output method. \nSTDOUT - default, \nFILE - Each certificate is written to file with host address as filename.";
  private static String OPTION_SHORT_FILE_PATH_LIST = "f";
  private static String OPTION_LONG_FILE_PATH_LIST = "file-path";
  private static String OPTION_FILE_PATH_DESCRIPTION = "the path where output will be written to if output method is FILE. The current path will be used if not specified.";
  private boolean valid;
  private ICLIOptions cliOptions;

  private ICLIOptions processOptions(CommandLine line) {
    valid = true;
    if (line.hasOption(DefaultCLIOptionsContext.OPTION_SHORT_HELP)) {
      valid = false;
    } else if (!line.hasOption(DefaultCLIOptionsContext.OPTION_SHORT_ADDRESS_LIST)) {
      valid = false;
    }
    DefaultCLIOptions result = null;
    try {
      if (isValid()) {
        result = new DefaultCLIOptions();
        result.setIpAddressList(Arrays.asList(line.getOptionValues(DefaultCLIOptionsContext.OPTION_SHORT_ADDRESS_LIST)));
        String[] values = line.getOptionValues(DefaultCLIOptionsContext.OPTION_SHORT_PORT_LIST);
        parsePortList(result, values);
        String value = line.getOptionValue(DefaultCLIOptionsContext.OPTION_SHORT_OUTPUT_LIST);
        parseOutputType(result, value);
        value = line.getOptionValue(DefaultCLIOptionsContext.OPTION_SHORT_FILE_PATH_LIST);
        if (value == null) {
          result.setOutputFilePath("");
        } else {
          result.setOutputFilePath(value);
        }
      }
    } catch (IllegalArgumentException e) {
      valid = false;
      System.err.println(e.getMessage());
    }
    return result;
  }

  private void parsePortList(DefaultCLIOptions defaultCLIOptions, String[] values) throws IllegalArgumentException {
    if (values != null) {
      defaultCLIOptions.setPortList(Arrays.asList(values));
    } else {
      defaultCLIOptions.setPortList(defaultPorts());
    }
  }

  private List<String> defaultPorts() {
    List<String> result = new ArrayList<String>();
    result.add("80");
    result.add("443");
    return result;
  }

  private void parseOutputType(DefaultCLIOptions defaultCLIOptions, String value) throws IllegalArgumentException {
    OutputType outputType = null;
    if (value != null) {
      outputType = OutputType.parse(value);
    } else {
      outputType = OutputType.STDOUT;
    }
    if (outputType != null) {
      defaultCLIOptions.setOutputType(outputType);
    } else {
      throw new IllegalArgumentException("Unsupported output type: " + value);
    }
  }

  private CommandLine getOpts(Options options, String[] args) {
    CommandLine result = null;
    try {
      CommandLineParser parser = new DefaultParser();
      result = parser.parse(options, args);
    } catch (ParseException e) {
      System.err.println("Invalid argument list.");
    }
    return result;
  }

  private Options buildOpts() {
    Options result = new Options();
    result.addOption(DefaultCLIOptionsContext.OPTION_SHORT_HELP, DefaultCLIOptionsContext.OPTION_LONG_HELP, false, DefaultCLIOptionsContext.OPTION_HELP_DESCRIPTION);
    Option option = new Option(DefaultCLIOptionsContext.OPTION_SHORT_ADDRESS_LIST, DefaultCLIOptionsContext.OPTION_LONG_ADDRESS_LIST, true, DefaultCLIOptionsContext.OPTION_ADDRESS_LIST_DESCRIPTION);
    option.setArgs(Option.UNLIMITED_VALUES);
    result.addOption(option);
    option = new Option(DefaultCLIOptionsContext.OPTION_SHORT_PORT_LIST, DefaultCLIOptionsContext.OPTION_LONG_PORT_LIST, true, DefaultCLIOptionsContext.OPTION_PORT_LIST_DESCRIPTION);
    option.setArgs(Option.UNLIMITED_VALUES);
    result.addOption(option);
    option = new Option(DefaultCLIOptionsContext.OPTION_SHORT_OUTPUT_LIST, DefaultCLIOptionsContext.OPTION_LONG_OUTPUT_LIST, true, DefaultCLIOptionsContext.OPTION_OUTPUT_DESCRIPTION);
    result.addOption(option);
    option = new Option(DefaultCLIOptionsContext.OPTION_SHORT_FILE_PATH_LIST, DefaultCLIOptionsContext.OPTION_LONG_FILE_PATH_LIST, true, DefaultCLIOptionsContext.OPTION_FILE_PATH_DESCRIPTION);
    result.addOption(option);
    return result;
  }

  @Override
  public void initialize(String[] args) {
    Options options = buildOpts();
    CommandLine line = getOpts(options, args);
    if (line != null) {
      this.cliOptions = processOptions(line);
    }
  }

  @Override
  public boolean isValid() {
    return valid;
  }

  @Override
  public ICLIOptions getCLIOptions() {
    return cliOptions;
  }

  @Override
  public String getHelp() {
    Options options = buildOpts();
    HelpFormatter formatter = new HelpFormatter();
    StringWriter writer = new StringWriter();
    PrintWriter printWriter = new PrintWriter(writer);
    formatter.printHelp(printWriter, 80, DefaultCLIOptionsContext.APP_NAME, null, options, 5, 5, null);
    printWriter.flush();
    printWriter.close();
    String result = writer.toString();
    writer.flush();
    try {
      writer.close();
    } catch (IOException e) {
      e.printStackTrace();
    }
    return result;
  }
}
