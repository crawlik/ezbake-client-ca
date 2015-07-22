package ezbake.clientca.cli;

import ezbake.clientca.cli.commands.*;

import org.kohsuke.args4j.Argument;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.Option;
import org.kohsuke.args4j.ParserProperties;
import org.kohsuke.args4j.spi.SubCommand;
import org.kohsuke.args4j.spi.SubCommandHandler;
import org.kohsuke.args4j.spi.SubCommands;

public class App implements Runnable {

    private String[] args;

    public App(String[] args) {
	this.args = args;
    }

    @Option(name="-h", aliases="--help", help=true)
    boolean help = false;

    @Argument(metaVar="command", handler=SubCommandHandler.class, required=true, usage="group command to execute")
    @SubCommands({
            @SubCommand(name="gen-cert", impl=GenerateCertificate.class)
    })
    ClientCACommand command;

    @Override
    public void run() {
        CmdLineParser parser = new CmdLineParser(this, ParserProperties.defaults().withUsageWidth(120));
        try {
            parser.parseArgument(args);
            if (help) {
                System.out.println("usage: java -jar client-ca-2.1.jar command [options]");
                parser.printUsage(System.out);
            } else {
		command.run();
            }
        } catch(CmdLineException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    public static void main(String[] args) {
        new App(args).run();
    }
}
