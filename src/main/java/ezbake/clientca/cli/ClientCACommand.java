package ezbake.clientca.cli;

import org.kohsuke.args4j.Option;

public abstract class ClientCACommand implements Runnable {
    @Option(name="-h", aliases="--help", help=true)
    boolean help = false;
}
