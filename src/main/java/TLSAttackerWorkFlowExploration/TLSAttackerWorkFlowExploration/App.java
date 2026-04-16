package TLSAttackerWorkFlowExploration.TLSAttackerWorkFlowExploration;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import config.OpenSSLServerConfig;
import config.TlsClientConfig;
import config.TlsClientConfigForTLS12;
import config.TlsClientConfigForTLS13;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import executer.TlsWorkflowExecutor;
import serverlauncher.OpenSSLServerLauncher;
import utils.MessageToJson;
import utils.TraceToString;
import workflow.TlsWorkflowBuilderForTLS13;
import workflow.TlsWorkflowBuilder;
import workflow.TlsWorkflowBuilderForTLS12;

public class App 
{

    public static void main( String[] args )
    {
    	String tlsVersion = "TLS13";
    	
    	
        // Register BouncyCastle for crypto support
    	Security.insertProviderAt(new BouncyCastleProvider(), 1);
    	
    	// Get OpenSSL server default configuration
    	OpenSSLServerConfig opensslServerConfig = tlsVersion.equals("TLS13") 
    		    ? OpenSSLServerConfig.defaultTls13() 
    		    : OpenSSLServerConfig.defaultTls12();
    	
    	
        // Launch OpenSSL server with TLS default configuration
    	OpenSSLServerLauncher launcher = new OpenSSLServerLauncher(opensslServerConfig);
  
        try {
        	launcher.start();
        } catch (Exception e) {
            System.err.println("Unable to start OpenSSL server: " + e.getMessage());
            System.err.println("Make sure OpenSSL is installed: openssl version");
            return;
        }
        
        
        try {
        	
        	// Get TLS client configuration
        	TlsClientConfig clientConfig = tlsVersion.equals("TLS13")
        			? TlsClientConfigForTLS13.getInstance()
        		    : TlsClientConfigForTLS12.getInstance();

        	// Build workflow trace (ClientHello, receive ServerHello, etc.)
        	TlsWorkflowBuilder builder = tlsVersion.equals("TLS13")
        			? new TlsWorkflowBuilderForTLS13()
        		    : new TlsWorkflowBuilderForTLS12();
        	
            WorkflowTrace trace = builder.build();   

            // Execute handshake against OpenSSL server
            TlsWorkflowExecutor executor = new TlsWorkflowExecutor(clientConfig, trace);
            State state  = executor.execute();
            
            // Export captured messages to JSON file
            MessageToJson mtj = new MessageToJson(state.getWorkflowTrace());
            mtj.informationsExtraction(tlsVersion);
            
            // Print human-readable trace to console
            System.out.println((new TraceToString(state.getWorkflowTrace())).toString());

        } finally {
        	// Always kill OpenSSL process
        	launcher.stop();
        }
    	
            
     }
}