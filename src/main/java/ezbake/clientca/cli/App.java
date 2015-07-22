package ezbake.clientca;

import org.kohsuke.args4j.Option;

public class Cli {
    @Option(name="-principal",usage="User principal to create a certificate for")
    public String principalName;

    public void run() {
	System.out.println("got principal name: " + principalName);
    }
}
