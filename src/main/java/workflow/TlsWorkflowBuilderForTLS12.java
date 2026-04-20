package workflow;

import config.TlsClientConfig;
import config.TlsClientConfigForTLS12;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.*;


public class TlsWorkflowBuilderForTLS12 implements TlsWorkflowBuilder {
	
	private WorkflowTrace trace;
	
	public TlsWorkflowBuilderForTLS12() {
		this.trace = new WorkflowTrace();
	}
	
    
	/**
	 * Constructs a complete TLS 1.2 handshake.
	 *
	 * @return an unexecuted workflow trace
	 */
	public WorkflowTrace build(TlsClientConfig clientConfig) {

		//TlsClientConfigForTLS12 config = TlsClientConfigForTLS12.getInstance();
		
		/**
		 * Client -> Server
		 * ClientHello contains :
		 *    - supported TLS versions (up to TLS 1.2)
		 *    - cipher suites supported by the client
		 *    - random bytes for session establishment
		 */
	    trace.addTlsAction(new SendAction(
	            new ClientHelloMessage(clientConfig.build())
	    ));

	    /**
	     * Server -> Client
	     *   - ServerHello : selects cipher suite and sends server random
	     *   - Certificate : server's certificate chain
	     *   - ServerHelloDone : indicates server has finished its part of the negotiation
	     */
	    trace.addTlsAction(new ReceiveAction(
	            new ServerHelloMessage(),
	            new CertificateMessage(),
	            new ServerHelloDoneMessage()
	    ));
	    
	    /**
	     * Client -> Server
	     *    - ClientKeyExchange : contains the pre-master secret (encrypted with server's RSA public key)
	     *    - ChangeCipherSpec : signals that subsequent messages will be encrypted
	     *    - Finished : MAC over the entire handshake (encrypted)
	     */
	    trace.addTlsAction(new SendAction(
	            new RSAClientKeyExchangeMessage(),
	            new ChangeCipherSpecMessage(),
	            new FinishedMessage()
	    ));
        
	    /**
	    //RSA only
	    trace.addTlsAction(new SendAction(
	            new RSAClientKeyExchangeMessage(),
	            new ChangeCipherSpecMessage(),
	            new FinishedMessage()
	    ));
	    
	    // ECDHE only
	    trace.addTlsAction(new SendAction(
	        new ECDHClientKeyExchangeMessage(),
	        new ChangeCipherSpecMessage(),
	        new FinishedMessage()
	    ));

	    // DHE only
	    trace.addTlsAction(new SendAction(
	        new DHClientKeyExchangeMessage(),
	        new ChangeCipherSpecMessage(),
	        new FinishedMessage()
	    ));
	    **/
	    
	    /**
	     * Server -> Client
	     *    - ChangeCipherSpec : server signals encryption will start
	     *    - Finished : server MAC over the entire handshake (encrypted)
	     */
	    trace.addTlsAction(new ReceiveAction(
	            new ChangeCipherSpecMessage(),
	            new FinishedMessage()
	    ));
	    

	    return trace;
	}

}
