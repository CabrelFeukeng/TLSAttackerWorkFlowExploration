package handler;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Handler for processing and analyzing TLS messages from a workflow trace.
 * Provides methods to extract sent/received messages, check handshake status,
 * and retrieve application data.
 */
public class TlsMessageHandler {
	
	  private static final Logger LOG = LoggerFactory.getLogger(TlsMessageHandler.class);

	  private State state;           // The TLS state containing connection and workflow information
	  private WorkflowTrace trace;   // The workflow trace containing all TLS actions
	    
	  /**
	   * Constructs a TlsMessageHandler with the given TLS state.
	   * @param state The TLS state from which to extract the workflow trace
	   */
	  public TlsMessageHandler(State state) {
	      this.state  = state;
	      this.trace  = state.getWorkflowTrace();
	  }
	  
	  /**
	   * Checks if the handshake completed successfully.
	   * @return true if all actions executed as planned, false otherwise
	   */
	  public boolean isHandshakeComplete() {
		    for (TlsAction action : trace.getTlsActions()) {
		        if (!action.executedAsPlanned()) {
		            return false;  // At least one action failed
		        }
		    }
		    return true;  // All actions executed successfully
	  }
	  
	  /**
	   * Retrieves all messages that were sent during the workflow.
	   * @return List of ProtocolMessages that were sent
	   */
	  public List<ProtocolMessage> getSentMessages() {
	        List<ProtocolMessage> sent = new ArrayList<>();
	        for (TlsAction action : trace.getTlsActions()) {
	            if (action instanceof SendAction) {
	            	List<ProtocolMessage> msgs = ((SendAction) action).getSentMessages();
	            	if (msgs != null) {
	            	    sent.addAll(msgs);  // Add all messages sent in this action
	            	}
	            }
	        }
	        return sent;
	   }
	  
	  /**
	   * Retrieves all messages that were received during the workflow.
	   * @return List of ProtocolMessages that were received
	   */
	   public List<ProtocolMessage> getReceivedMessages() {
	        List<ProtocolMessage> received = new ArrayList<>();
	        for (TlsAction action : trace.getTlsActions()) {
	            if (action instanceof ReceiveAction) {
	                List<ProtocolMessage> msgs = ((ReceiveAction) action).getReceivedMessages();
	                if (msgs != null) received.addAll(msgs);  // Add all messages received in this action
	            }
	        }
	        return received;
	    }
	   
	   /**
	    * Checks if an alert message was received during the workflow.
	    * @return true if at least one AlertMessage was received, false otherwise
	    */
	   public boolean receivedAlert() {
	        return getReceivedMessages().stream()
	            .anyMatch(m -> m instanceof AlertMessage);  // Check for any alert message in received messages
	    }
	   
	   /**
	    * Extracts and concatenates all application data from received messages.
	    * @return Concatenated byte array of all application data
	    */
	   public byte[] getApplicationData() {
	        return getReceivedMessages().stream()
	            .filter(m -> m instanceof ApplicationMessage)  // Keep only application messages
	            .map(m -> ((ApplicationMessage) m).getData().getValue())  // Extract the data from each message
	            .reduce(new byte[0], (a, b) -> {
	                // Merge byte arrays: a = accumulated result, b = new data to add
	                byte[] merged = new byte[a.length + b.length];
	                System.arraycopy(a, 0, merged, 0, a.length);
	                System.arraycopy(b, 0, merged, a.length, b.length);
	                return merged;
	            });
	    }
	   
	   /**
	    * Logs a summary of the TLS workflow including handshake status,
	    * message counts, and a list of received messages.
	    */
	   public void logSummary() {
	        LOG.info("=== Workflow Summary ===");
	        LOG.info("Handshake complete  : {}", isHandshakeComplete());
	        LOG.info("Messages sent       : {}", getSentMessages().size());
	        LOG.info("Messages received   : {}", getReceivedMessages().size());
	        LOG.info("Alert received      : {}", receivedAlert());

	        // Log each received message type
	        getReceivedMessages().forEach(msg ->
	            LOG.info("  ← {}", msg.getClass().getSimpleName())
	        );
	    }
	   
	   /**
	    * Returns the TLS state associated with this handler.
	    * @return The current State object
	    */
	   public State getState() {
		   return this.state;
	   }
	   
}