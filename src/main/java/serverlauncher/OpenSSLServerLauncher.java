package serverlauncher;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import config.OpenSSLServerConfig;

import java.io.*;
import java.net.ServerSocket;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

/**
 * Lance un serveur OpenSSL s_server à partir d'une {@link OpenSSLServerConfig}.
 *
 * <pre>
 * OpenSSLServerConfig config = OpenSSLServerConfig.builder()
 *     .version(TlsVersion.TLS_1_2)
 *     .cipherSuite(CipherSuite.ECDHE_RSA_AES256_GCM_SHA384)
 *     .verbose(true)
 *     .build();
 *
 * OpenSSLServerLauncher launcher = new OpenSSLServerLauncher(config);
 * launcher.start();
 * // ... tests ...
 * launcher.stop();
 * </pre>
 */
public class OpenSSLServerLauncher {

    private static final Logger LOG = LoggerFactory.getLogger(OpenSSLServerLauncher.class);

    private static final int STARTUP_TIMEOUT_MS   = 5_000;
    private static final int PORT_POLL_INTERVAL_MS = 200;
    private static final int PORT_CHECK_TIMEOUT_MS = 300;

    private final OpenSSLServerConfig config;
    private Process serverProcess;

    // Capture des premières lignes pour diagnostics en cas de crash
    private final List<String> startupOutput = new ArrayList<>();

    // -----------------------------------------------------------------------
    // Constructeurs
    // -----------------------------------------------------------------------
    public OpenSSLServerLauncher(OpenSSLServerConfig config) {
        this.config = config;
    }

    public OpenSSLServerLauncher() {
        this(OpenSSLServerConfig.defaultTls12());
    }

    // -----------------------------------------------------------------------
    // Cycle de vie
    // -----------------------------------------------------------------------

    public void start() throws IOException, InterruptedException {
        LOG.info("Configuration: {}", config);
        checkPortAvailable();
        ensureCertificateExists();
        launchServer();
        waitForServerReady();
    }

    public void stop() {
        if (!isRunning()) return;

        LOG.info("Stopping OpenSSL server...");
        serverProcess.destroy();
        try {
            boolean exited = serverProcess.waitFor(5, TimeUnit.SECONDS);
            if (!exited) {
                LOG.warn("Server did not stop gracefully — forcing kill.");
                serverProcess.destroyForcibly();
            } else {
                LOG.info("OpenSSL server stopped.");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOG.warn("Interrupted during server shutdown.");
        }
    }

    public boolean isRunning() {
        return serverProcess != null && serverProcess.isAlive();
    }

    public OpenSSLServerConfig getConfig() {
        return config;
    }

    // -----------------------------------------------------------------------
    // Pré-vérifications
    // -----------------------------------------------------------------------

    /**
     * Vérifie que le port est libre AVANT de lancer OpenSSL.
     * Si le port est occupé on échoue tôt avec un message clair,
     * plutôt qu'un "exit: 1" cryptique depuis OpenSSL.
     */
    private void checkPortAvailable() throws IOException {
        try (ServerSocket probe = new ServerSocket(config.port())) {
            probe.setReuseAddress(true);
            LOG.debug("Port {} is available.", config.port());
        } catch (IOException e) {
            throw new IOException(
                "Port " + config.port() + " is already in use. "
                + "Stop any existing server or change the port in the config.",
                e
            );
        }
    }

    private void ensureCertificateExists() throws IOException, InterruptedException {
        Path certPath = Paths.get(config.certFile());
        Path keyPath  = Paths.get(config.keyFile());

        if (Files.exists(certPath) && Files.exists(keyPath)) {
            LOG.info("Certificate found — reusing {} / {}", config.certFile(), config.keyFile());
            return;
        }

        Files.createDirectories(certPath.getParent());
        LOG.info("Generating self-signed certificate...");

        ProcessBuilder pb = new ProcessBuilder(
            "openssl", "req",
            "-x509",
            "-newkey", "rsa:2048",  // ou "rsa:2048"
            "-keyout", config.keyFile(),
            "-out",    config.certFile(),
            "-days",   "365",
            "-nodes",
            "-subj",   "/CN=" + config.host()
        );
        
        pb.redirectErrorStream(true);
        Process proc = pb.start();
        drainToLog(proc.getInputStream(), "openssl-keygen");

        int exit = proc.waitFor();
        if (exit != 0) {
            throw new IOException("Certificate generation failed (exit: " + exit + ")");
        }
        LOG.info("Certificate generated: {} / {}", config.certFile(), config.keyFile());
    }

    // -----------------------------------------------------------------------
    // Lancement
    // -----------------------------------------------------------------------

    private void launchServer() throws IOException {
        List<String> command = config.toCommand();
        LOG.info("Starting OpenSSL server — command: {}", String.join(" ", command));

        ProcessBuilder pb = new ProcessBuilder(command);
        
        pb.redirectErrorStream(true);
        pb.inheritIO();
        serverProcess = pb.start();

        startupOutput.clear();

        // Lecture de stdout/stderr dans un thread dédié.
        // Les 30 premières lignes sont conservées pour le message d'erreur
        // en cas de crash prématuré.
        Thread logThread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(serverProcess.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    synchronized (startupOutput) {
                        if (startupOutput.size() < 30) startupOutput.add(line);
                    }
                    LOG.debug("[openssl-server] {}", line);
                }
            } catch (IOException e) {
                LOG.warn("[openssl-server] Read interrupted: {}", e.getMessage());
            }
        });
        logThread.setDaemon(true);
        logThread.start();

        LOG.info("OpenSSL process started.");
    }

    // -----------------------------------------------------------------------
    // Attente de disponibilité
    // -----------------------------------------------------------------------

    private void waitForServerReady() throws InterruptedException {
        LOG.info("Waiting for server on {}:{}...", config.host(), config.port());

        long deadline = System.currentTimeMillis() + STARTUP_TIMEOUT_MS;
        int attempt = 0;

        while (System.currentTimeMillis() < deadline) {
            attempt++;
            Thread.sleep(PORT_POLL_INTERVAL_MS);

            if (!serverProcess.isAlive()) {
                Thread.sleep(200); // laisser le thread de log vider le buffer
                throw new IllegalStateException(buildCrashMessage(serverProcess.exitValue()));
            }

            if (isPortOpen()) {
                LOG.info("Server ready on {}:{} (attempt {})", config.host(), config.port(), attempt);
                return;
            }

            LOG.debug("Attempt {} — server not ready yet...", attempt);
        }

        serverProcess.destroyForcibly();
        throw new IllegalStateException(
            "Server did not become ready within " + STARTUP_TIMEOUT_MS + "ms "
            + "on " + config.host() + ":" + config.port()
        );
    }

    private String buildCrashMessage(int exitCode) {
        StringBuilder sb = new StringBuilder();
        sb.append("OpenSSL server stopped prematurely (exit: ").append(exitCode).append(").\n");
        sb.append("Command: ").append(config).append("\n");

        synchronized (startupOutput) {
            if (!startupOutput.isEmpty()) {
                sb.append("OpenSSL output:\n");
                startupOutput.forEach(line -> sb.append("  > ").append(line).append("\n"));
            } else {
                sb.append("(no output captured)\n");
                sb.append("Tip: check that openssl is installed with `openssl version`");
            }
        }
        return sb.toString();
    }

    private boolean isPortOpen() {
        try (java.net.Socket socket = new java.net.Socket()) {
            socket.connect(
                new java.net.InetSocketAddress(config.host(), config.port()),
                PORT_CHECK_TIMEOUT_MS
            );
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private void drainToLog(InputStream is, String prefix) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
            String line;
            while ((line = reader.readLine()) != null) {
                LOG.debug("[{}] {}", prefix, line);
            }
        } catch (IOException e) {
            LOG.warn("[{}] Read interrupted: {}", prefix, e.getMessage());
        }
    }
}