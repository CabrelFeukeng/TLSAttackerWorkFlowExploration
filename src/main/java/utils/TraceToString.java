package utils;

import java.util.Collections;
import java.util.List;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;

public class TraceToString {
	
	private WorkflowTrace trace;
	
	public TraceToString(WorkflowTrace trace) {
		this.trace = trace;
	}
	
	public String toString() {
		
	    if (trace == null) {
	        return "TlsWorkflowBuilder [ no trace builded ]";
	    }

	    StringBuilder sb = new StringBuilder();
	    List<TlsAction> actions = trace.getTlsActions();

	    sb.append("\n══════════════════════════════════════════════════ \n");
	    sb.append(  "           TLS WORKFLOW TRACE                      \n");
	    sb.append(  "══════════════════════════════════════════════════\n");
	    sb.append(String.format("  Number of actions : %-28d %n", actions.size()));
	    sb.append(  "══════════════════════════════════════════════════\n");

	    for (int i = 0; i < actions.size(); i++) {
	        TlsAction action = actions.get(i);

	        String actionType  = action.getClass().getSimpleName();
	        String direction   = resolveDirection(action);
	        String executed    = action.isExecuted()
	                             ? "✔ executed"
	                             : "✘ no executed";
	        String asPlanned   = action.isExecuted()
	                             ? (action.executedAsPlanned() ? "✔ as expected" : "✘ not as expected")
	                             : "─";

	        sb.append(String.format("  [%02d] %s %-38s %n", i + 1, direction, actionType));
	        sb.append(String.format("       Statut   : %-31s %n", executed));
	        sb.append(String.format("       Result : %-31s %n", asPlanned));

	        List<ProtocolMessage> messages = resolveMessages(action);
	        if (messages != null && !messages.isEmpty()) {
	            sb.append("       Messages :                                 \n");
	            for (ProtocolMessage msg : messages) {
	                String msgName = msg.getClass().getSimpleName();
	                sb.append(String.format("         • %-39s %n", msgName));
	            }
	        }

	        if (i < actions.size() - 1) {
	            sb.append("  ────────────────────────────────────────────── \n");
	        }
	    }

	    sb.append("══════════════════════════════════════════════════");
	    return sb.toString();
	}

	private String resolveDirection(TlsAction action) {
	    if (action instanceof SendAction)    return "→ SEND   ";
	    if (action instanceof ReceiveAction) return "← RECEIVE";
	    return "  OTHER  ";
	}

	private List<ProtocolMessage> resolveMessages(TlsAction action) {
	    if (action instanceof SendAction) {
	        List<ProtocolMessage> sent = ((SendAction) action).getSentMessages();
	        if (sent != null && !sent.isEmpty()) return sent;
	        return ((SendAction) action).getConfiguredMessages();
	    }
	    if (action instanceof ReceiveAction) {
	        List<ProtocolMessage> received = ((ReceiveAction) action).getReceivedMessages();
	        if (received != null && !received.isEmpty()) return received;
	        return ((ReceiveAction) action).getExpectedMessages();
	    }
	    return Collections.emptyList();
	}

}
