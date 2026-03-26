package TLSAttackerWorkFlowExploration.TLSAttackerWorkFlowExploration;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import executer.TlsWorkflowExecutor;
import handler.TlsMessageHandler;
import serverlauncher.OpenSSLServerLauncher;
import utils.TraceToString;
import workflow.TlsWorkflowBuilder;

public class App 
{
    public static void main( String[] args )
    {
    	Security.insertProviderAt(new BouncyCastleProvider(), 1);
    	
    	OpenSSLServerLauncher server = new OpenSSLServerLauncher();
        try {
            server.start();
        } catch (Exception e) {
            System.err.println("Unable to start OpenSSL server: " + e.getMessage());
            System.err.println("Make sure OpenSSL is installed: openssl version");
            return;
        }
        
        try {

        	// Build the workflow
            TlsWorkflowBuilder builder = new TlsWorkflowBuilder();
            WorkflowTrace trace = builder.buildFullHandshake();
            

            // Execution
            TlsWorkflowExecutor executor = TlsWorkflowExecutor.getInstance();
            State state  = executor.execute(trace);
            
            // Results analysis
            TlsMessageHandler handler = new TlsMessageHandler(state);
            handler.logSummary();

            // Exploration of received data
            if (handler.isHandshakeComplete()) {
                byte[] data = handler.getApplicationData();
                System.out.println("Response: " + new String(data));
            }
            handler.logSummary();
            
            System.out.println((new TraceToString(state.getWorkflowTrace())).toString());

        } finally {
            server.stop();
        }
    	
            
     }
}