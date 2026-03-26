package workflow;

import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.*;


public class TlsWorkflowBuilder {
	
	private WorkflowTrace trace;
	
	public TlsWorkflowBuilder() {
		this.trace = new WorkflowTrace();
	}
	
    /**
     * 
     * @return not executed trace
     */
	public WorkflowTrace buildFullHandshake() {

		trace.addTlsAction(new SendAction(
				new ClientHelloMessage()
		));
		
		trace.addTlsAction(new ReceiveAction(
				new ServerHelloMessage(),
				new CertificateMessage(),
				new ServerHelloDoneMessage()
		));
		
		trace.addTlsAction(new SendAction(
				new RSAClientKeyExchangeMessage(),
	            new ChangeCipherSpecMessage(),
	            new FinishedMessage()
	    ));
		
		trace.addTlsAction(new ReceiveAction(
	            new ChangeCipherSpecMessage(),
	            new FinishedMessage()
	    ));

		return trace;
	}
	
    /**
     * 
     * @param payload : data to send after the handshake phase
     * @return
     */
	public WorkflowTrace buildHandshakeThenSendData(byte[] payload) {
		WorkflowTrace trace = buildFullHandshake();
		
		ApplicationMessage appMsg = new ApplicationMessage();
		appMsg.setData(payload);
		trace.addTlsAction(new SendAction(appMsg));
		
		trace.addTlsAction(new GenericReceiveAction());
		
		return trace;
	}
	
    /**
     * 
     * @return the trace of alert messages
     */
	public WorkflowTrace buildSendAlert() {
        WorkflowTrace trace = buildFullHandshake();

        AlertMessage alert = new AlertMessage();
        alert.setConfig(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY);
        trace.addTlsAction(new SendAction(alert));

        return trace;
    }
	
}
