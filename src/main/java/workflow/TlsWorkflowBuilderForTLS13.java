package workflow;

import config.TlsClientConfigForTLS13;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;

public class TlsWorkflowBuilderForTLS13 implements TlsWorkflowBuilder  {
	
    private WorkflowTrace trace;
	
	public TlsWorkflowBuilderForTLS13(){
		this.trace = new WorkflowTrace();
	}
	
	/**
	 * Constructs a complete TLS 1.3 handshake.
	 * @return not executed workflow trace
	 */
	public WorkflowTrace build() {
		
		TlsClientConfigForTLS13 config = TlsClientConfigForTLS13.getInstance();

		/**
		 * Client -> Server
		 * ClientHello contains :
		 *     - supported versions : TLS 1.3
		 *     - key_share : client's ECDHE public key
		 *     - signature_algorithms
		 */
	    trace.addTlsAction(new SendAction(
	    		new ClientHelloMessage((Config) config.build())
	    ));

	    
	    /**
	     * Server -> Client
	     *      - ServerHello : selects cipher suite and sends its key_share
	     *      - EncryptedExtensions : encrypted extensions
	     *      - Certificate : server certificate (already encrypted in TLS 1.3)
	     *      - CertificateVerify : proof that the server holds the private key
	     *      - Finished : MAC over the entire handshake
	     */
	    trace.addTlsAction(new ReceiveAction(
	        new ServerHelloMessage(),
	        new EncryptedExtensionsMessage(),
	        new CertificateMessage(),
	        new CertificateVerifyMessage(),
	        new FinishedMessage()
	    ));
	    
	    /**
	     * Client -> Server
	     *     - Finished : client MAC over the complete handshake (no ClientKeyExchange, no ChangeCipherSpec)
	     */
	    trace.addTlsAction(new SendAction(
	        new FinishedMessage()
	    ));

	    return trace;
	}
	
}
