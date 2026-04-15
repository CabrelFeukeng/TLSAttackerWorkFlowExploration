package TLSAttackerWorkFlowExploration.TLSAttackerWorkFlowExploration;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import config.OpenSSLServerConfig;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import executer.TlsWorkflowExecutor;
import handler.TlsMessageHandler;
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

    	Security.insertProviderAt(new BouncyCastleProvider(), 1);
        
        /* */
    	OpenSSLServerLauncher launcher = new OpenSSLServerLauncher(OpenSSLServerConfig.defaultTls13());
  
        try {
        	launcher.start();
        } catch (Exception e) {
            System.err.println("Unable to start OpenSSL server: " + e.getMessage());
            System.err.println("Make sure OpenSSL is installed: openssl version");

            return;
        }
        
        
        try {

        	// Build the workflow
        	TlsWorkflowBuilder builder = new TlsWorkflowBuilderForTLS13();
            WorkflowTrace trace = builder.build();    

            // Execution
            TlsWorkflowExecutor executor = TlsWorkflowExecutor.getInstance();
            State state  = executor.execute(trace, "TLS_13");
            
            // Results analysis
            TlsMessageHandler handler = new TlsMessageHandler(state);
            handler.logSummary();
            
            MessageToJson mtj = new MessageToJson(state.getWorkflowTrace());
            mtj.informationsExtraction("TLS13");
            
            System.out.println((new TraceToString(state.getWorkflowTrace())).toString());

        } finally {
        	launcher.stop();
        }
    	
            
     }
}