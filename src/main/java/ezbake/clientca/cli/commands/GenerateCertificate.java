package ezbake.clientca.cli.commands;

import ezbake.clientca.cli.ClientCACommand;

import org.kohsuke.args4j.Option;

public class GenerateCertificate extends ClientCACommand {
    @Option(name="-principal",usage="User principal to create a certificate for",required=true)
    public String principalName;

    @Override
    public void run() {
	System.out.println("principal name: " + principalName);	
    }
}
