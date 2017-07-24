package x509scan;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.log4j.PropertyConfigurator;

public class Main {

  private static final String LOG4J_CONFIGURATION = "log4j.configuration";

  private static Log _log = LogFactory.getLog("x509scan.Main");

  private ICLIOptions cliOptions;

  public static void main(String[] args) {
    String log4j = System.getProperty(Main.LOG4J_CONFIGURATION, "log4j.properties");
    if (!new File(log4j).exists()) {
      System.err.println("Log4j config file does NOT exist.");
      return;
    }
    // TODO Remove this
    PropertyConfigurator.configure(log4j);
    Main._log.debug("Starting ...");

    Main m = new Main();
    if (!m.initialize(args)) {
      Main._log.fatal("Aborting.");
      System.exit(1);
    }
    m.doScan();
  }

  public boolean initialize(String[] args) {
    boolean result;
    CLIOptionsContextFactory cliOptionsContextFactory = new CLIOptionsContextFactory();
    ICLIOptionsContext cliContext = cliOptionsContextFactory.createContext();
    cliContext.initialize(args);
    result = cliContext.isValid();
    if (!result) {
      System.out.println(cliContext.getHelp());
    } else {
      this.cliOptions = cliContext.getCLIOptions();
    }
    return result;
  }

  private OutputMethod createOutputMethod() {
    OutputMethod result;
    OutputType outputType = this.cliOptions.getOutputType();
    if (OutputType.FILE.equals(outputType)) {
      String outputFilePath = this.cliOptions.getOutputFilePath();
      File f = new File(outputFilePath);
      result = new FileOutputMethod(f.getAbsolutePath());
    } else {
      result = new StdOutputMethod();
    }
    return result;
  }

  private void doScan() {
    Validator validator = new Validator(this.cliOptions);
    validator.validate();

    OutputMethod outputMethod = createOutputMethod();

    int maxThreadCount = this.cliOptions.getMaxWorkerThreadPoolSize();
    int threadCount = maxThreadCount;

    List<String> hostList = this.cliOptions.getIpAddressList();
    List<String> portList = this.cliOptions.getPorts();

    threadCount = hostList.size();
    if (threadCount > maxThreadCount) {
      threadCount = maxThreadCount;
    }

    LinkedBlockingQueue<IMessage> writeMessageQueue = new LinkedBlockingQueue<IMessage>();
    LinkedBlockingQueue<IMessage> readMessageQueue = new LinkedBlockingQueue<IMessage>();
    LinkedBlockingQueue<IMessage> myWriteMessageQueue = readMessageQueue;
    LinkedBlockingQueue<IMessage> myReadMessageQueue = writeMessageQueue;
    createWorkers(writeMessageQueue, readMessageQueue, threadCount);
    scheduleWorkers(myWriteMessageQueue, hostList, portList);
    queueStopWorkers(myWriteMessageQueue, threadCount);
    handleResponseFromWorkers(outputMethod, myReadMessageQueue, threadCount);
    Main._log.debug("Exiting.");
  }

  private void createWorkers(LinkedBlockingQueue<IMessage> writeMessageQueue, LinkedBlockingQueue<IMessage> readMessageQueue, int threadCount) {
    Main._log.debug("Creating " + threadCount + " X509 Workers");
    ThreadGroup threadGroup = new ThreadGroup("X509 ");
    for (int i = 0; i < threadCount; i++) {
      String name = "X509Worker " + i;
      Main._log.debug("Creating worker named: " + name);
      X509Worker x509Worker = new X509Worker(name, readMessageQueue, writeMessageQueue);
      Thread t = new Thread(threadGroup, x509Worker, name);
      t.start();
    }
  }

  private void scheduleWorkers(LinkedBlockingQueue<IMessage> myWriteMessageQueue, List<String> hostList, List<String> portList) {
    Main._log.debug("Scheduling work units for X509 Worker pool");
    for (String host : hostList) {
      for (String port : portList) {
        int p = Integer.parseInt(port);
        ProcessMessage processMessage = new ProcessMessage(host, p, new ByteArrayOutputStream());
        myWriteMessageQueue.offer(processMessage);
      }
    }
  }

  private void queueStopWorkers(LinkedBlockingQueue<IMessage> myWriteMessageQueue, int threadCount) {
    Main._log.debug("Writing stop messages to queue of X509 Workers");
    // Instructing the threads to exit cleanly.
    for (int i = 0; i < threadCount; i++) {
      myWriteMessageQueue.offer(new StopMessage());
    }
  }

  private void handleResponseFromWorkers(OutputMethod outputMethod, LinkedBlockingQueue<IMessage> myReadMessageQueue, int threadCount) {
    int stopCnt = 0;
    while (stopCnt < threadCount) {
      try {
        IMessage message = myReadMessageQueue.take();
        IMessage.MessageType messageType = message.getMessageType();
        if (IMessage.MessageType.PROCESS.equals(messageType)) {
          ProcessMessage processMessage = (ProcessMessage) message;
          ByteArrayOutputStream out = processMessage.getOut();
          String host = processMessage.getHost();
          int port = processMessage.getPort();
          byte[] data = processMessage.getData();
          String cname = processMessage.getCName();
          outputMethod.writeOutput(host, port, data, cname);
        } else {
          stopCnt++;
          Main._log.debug("Received stop message from " + stopCnt + " of " + threadCount + " workers");
        }
      } catch (InterruptedException e) {
        Main._log.debug(e);
      } catch (IOException e) {
        Main._log.debug(e);
      }
    }
  }

}