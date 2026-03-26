package serverlauncher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.*;
import java.util.concurrent.TimeUnit;


public class OpenSSLServerLauncher {

    private static final Logger LOG = LoggerFactory.getLogger(OpenSSLServerLauncher.class);

    private static final String CERT_FILE = "src/main/resources/data/server.crt";
    private static final String KEY_FILE  = "src/main/resources/data/server.key";
    private static final String HOST      = "localhost";
    private static final int    PORT      = 1234;

    private Process serverProcess;

    public void start() throws IOException, InterruptedException {
        ensureCertificateExists();
        launchServer();
        waitForServerReady();
    }

    public void stop() {
        if (serverProcess != null && serverProcess.isAlive()) {
            LOG.info("Stopping OpenSSL server...");
            serverProcess.destroy();
            try {
                serverProcess.waitFor(5, TimeUnit.SECONDS);
                LOG.info("OpenSSL server stopped");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                LOG.warn("Interruption during server shutdown");
            }
        }
    }

    public boolean isRunning() {
        return serverProcess != null && serverProcess.isAlive();
    }

    private void ensureCertificateExists() throws IOException, InterruptedException {
        if (Files.exists(Paths.get(CERT_FILE)) && Files.exists(Paths.get(KEY_FILE))) {
            LOG.info("Existing certificate found — reusing {} / {}", CERT_FILE, KEY_FILE);
            return;
        }

        LOG.info("Generating self-signed certificate...");

        ProcessBuilder pb = new ProcessBuilder(
            "openssl", "req",
            "-x509",
            "-newkey", "rsa:2048",
            "-keyout", KEY_FILE,
            "-out",    CERT_FILE,
            "-days",   "365",
            "-nodes",
            "-subj",   "/CN=localhost"
        );

        pb.redirectErrorStream(true);
        Process process = pb.start();

        // Log openssl output
        logProcessOutput(process, "openssl-keygen");

        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new IOException("Certificate generation failed (exit code: " + exitCode + ")");
        }

        LOG.info("Certificate generated: {} / {}", CERT_FILE, KEY_FILE);
    }

    private void launchServer() throws IOException {
        LOG.info("Starting OpenSSL server on {}:{}...", HOST, PORT);

        ProcessBuilder pb = new ProcessBuilder(
            "openssl", "s_server",
            "-accept",  String.valueOf(PORT),
            "-cert",    CERT_FILE,
            "-key",     KEY_FILE,
            "-tls1_2",
            "-msg",    
            "-state"    
        );

        pb.redirectErrorStream(true);
        serverProcess = pb.start();

        // Log server output in a dedicated thread
        Thread logThread = new Thread(() -> logProcessOutput(serverProcess, "openssl-server"));
        logThread.setDaemon(true);
        logThread.start();

        LOG.info("OpenSSL process started (PID available)");
    }

    private void waitForServerReady() throws InterruptedException {
        LOG.info("Waiting for server to become available...");

        int maxAttempts = 10;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            TimeUnit.MILLISECONDS.sleep(500);

            if (!serverProcess.isAlive()) {
                throw new IllegalStateException(
                    "OpenSSL server stopped prematurely (exit code: "
                    + serverProcess.exitValue() + ")"
                );
            }

            if (isPortOpen()) {
                LOG.info("Server ready on {}:{} (attempt {}/{})", HOST, PORT, attempt, maxAttempts);
                return;
            }

            LOG.debug("Attempt {}/{} — server not ready yet...", attempt, maxAttempts);
        }

        throw new IllegalStateException(
            "Server failed to start after " + maxAttempts + " attempts"
        );
    }

    private boolean isPortOpen() {
        try (java.net.Socket socket = new java.net.Socket()) {
            socket.connect(
                new java.net.InetSocketAddress(HOST, PORT),
                300 
            );
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private void logProcessOutput(Process process, String prefix) {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                LOG.debug("[{}] {}", prefix, line);
            }
        } catch (IOException e) {
            LOG.warn("[{}] Read interrupted: {}", prefix, e.getMessage());
        }
    }
}