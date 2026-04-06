package utils;

import java.util.Collections;
import java.util.List;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;

public class TraceToString {
	
	private static final String RESET = "\u001B[0m";
	private static final String BOLD = "\u001B[1m";
	private static final String DIM = "\u001B[2m";
	
	private static final String BLACK = "\u001B[30m";
	private static final String GREEN = "\u001B[32m";

	private static final String BRIGHT_RED = "\u001B[91m";
	private static final String BRIGHT_GREEN = "\u001B[92m";
	private static final String BRIGHT_BLUE = "\u001B[94m";
	private static final String BRIGHT_CYAN = "\u001B[96m";
	
	private WorkflowTrace trace;
	
	public TraceToString(WorkflowTrace trace) {
		this.trace = trace;
	}
	
	public String toString() {
		
	    if (trace == null) {
	        return BLACK + "⚠️  " + BOLD + "TlsWorkflowBuilder" + RESET + BLACK + " [ no trace built ]" + RESET;
	    }

	    StringBuilder sb = new StringBuilder();
	    List<TlsAction> actions = trace.getTlsActions();

	    // Header with gradient effect
	    sb.append(GREEN + BOLD + "\n╔══════════════════════════════════════════════════════════╗\n");
	    sb.append("║                    🔐 TLS WORKFLOW TRACE                 ║\n");
	    sb.append("╚══════════════════════════════════════════════════════════╝\n" + RESET);
	    
	    // Stats line
	    sb.append(GREEN + "  📊 " + BOLD + "Total Actions" + RESET + GREEN + " : " + RESET);
	    sb.append(BRIGHT_GREEN + BOLD + String.format("%-28d", actions.size()) + RESET);
	    sb.append(GREEN + " 🔄" + RESET + "\n");
	    sb.append(DIM + "  " + "─".repeat(54) + "\n" + RESET);

	    for (int i = 0; i < actions.size(); i++) {
	        TlsAction action = actions.get(i);

	        String actionType  = action.getClass().getSimpleName();
	        String direction   = resolveDirection(action);
	        String executed    = action.isExecuted()
	                             ? BRIGHT_GREEN + "✓ EXECUTED" + RESET
	                             : BRIGHT_RED + "✗ NOT EXECUTED" + RESET;
	        String asPlanned   = action.isExecuted()
	                             ? (action.executedAsPlanned() ? BRIGHT_GREEN + "✓ AS EXPECTED" + RESET : BRIGHT_RED + "✗ NOT AS EXPECTED" + RESET)
	                             : DIM + "— NOT APPLICABLE" + RESET;


	        // Action header with number and type
	        sb.append(String.format("\n  " + BLACK + BOLD + "[%02d]" + RESET + " %s %s\n", i + 1, direction, actionType));
	        sb.append(String.format("     " + BLACK + "📌 Status" + RESET + "   : %s\n", executed));
	        sb.append(String.format("     " + BLACK + "🎯 Result" + RESET + "   : %s\n", asPlanned));

	        List<ProtocolMessage> messages = resolveMessages(action);
	        if (messages != null && !messages.isEmpty()) {
	            sb.append("     " + GREEN + "📨 Messages" + RESET + " :\n");
	            for (ProtocolMessage msg : messages) {
	                String msgName = msg.getClass().getSimpleName();
	                String coloredMsg = colorizeMessage(msgName);
	                sb.append(String.format("        %s %s\n", getMessageIcon(msgName), coloredMsg));
	            }
	        }

	        if (i < actions.size() - 1) {
	            sb.append(DIM + "──────────────────────────────────────────────────────\n" + RESET);
	        }
	        
	    }

	    sb.append(BRIGHT_CYAN + "\n══════════════════════════════════════════════════════════\n" + RESET);
	    return sb.toString();
	}

	private String resolveDirection(TlsAction action) {
	    if (action instanceof SendAction)    return BRIGHT_GREEN + "📤 SEND    " + RESET;
	    if (action instanceof ReceiveAction) return BRIGHT_BLUE + "📥 RECEIVE " + RESET;
	    return DIM + "⚙️  OTHER   " + RESET;
	}
	
	private String getMessageIcon(String msgName) {
		if (msgName.contains("ClientHello")) return "🖥️";
		if (msgName.contains("ServerHello")) return "🖥️";
		if (msgName.contains("Certificate")) return "📜";
		if (msgName.contains("Finished")) return "✅";
		if (msgName.contains("Alert")) return "⚠️";
		if (msgName.contains("Application")) return "📄";
		if (msgName.contains("ChangeCipherSpec")) return "🔐";
		return "📦";
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
	
	private String colorizeMessage(String msgName) {
		// Color different message types for better readability
		if (msgName.contains("ClientHello")) return BRIGHT_GREEN + msgName + RESET;
		if (msgName.contains("ServerHello")) return BRIGHT_BLUE + msgName + RESET;
		if (msgName.contains("Certificate")) return BRIGHT_CYAN + msgName + RESET;
		if (msgName.contains("Finished")) return BRIGHT_PURPLE() + msgName + RESET;
		if (msgName.contains("Alert")) return BRIGHT_RED + msgName + RESET;
		if (msgName.contains("Application")) return BLACK + msgName + RESET;
		if (msgName.contains("ChangeCipherSpec")) return BLACK + msgName + RESET;
		return BLACK + msgName + RESET;
	}
	
	private String BRIGHT_PURPLE() {
		return "\u001B[95m";
	}
}
