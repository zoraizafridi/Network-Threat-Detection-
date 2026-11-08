package pk.ooad.ntd.notify;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

public final class SmtpMailer implements Mailer {

    private static final DateTimeFormatter DATE = DateTimeFormatter.RFC_1123_DATE_TIME;

    private final String host;
    private final int port;
    private final String from;
    private final List<String> recipients;
    private final String username;
    private final String password;
    private final boolean startTls;
    private final int timeoutMillis;

    public SmtpMailer(String host, int port, String from, List<String> recipients,
                      String username, String password, boolean startTls, int timeoutMillis) {
        this.host = host == null ? "" : host.trim();
        this.port = port <= 0 ? 587 : port;
        this.from = from == null || from.isBlank() ? "ntd@localhost" : from.trim();
        this.recipients = recipients == null ? List.of() : recipients;
        this.username = username == null ? "" : username;
        this.password = password == null ? "" : password;
        this.startTls = startTls;
        this.timeoutMillis = Math.max(500, timeoutMillis);
    }

    @Override
    public void send(String subject, String body) throws IOException {
        if (host.isEmpty() || recipients.isEmpty()) {
            throw new IOException("smtp host or recipient is missing");
        }
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMillis);
            socket.setSoTimeout(timeoutMillis);
            Conversation conversation = new Conversation(socket);
            conversation.expect("220", "greeting");
            String capabilities = conversation.ehlo();
            if (startTls) {
                if (!capabilities.toUpperCase(Locale.ROOT).contains("STARTTLS")) {
                    throw new IOException("smtp server does not offer STARTTLS");
                }
                conversation.command("STARTTLS", "220");
                conversation.upgrade();
                conversation.ehlo();
            }
            if (!username.isEmpty()) {
                conversation.authenticate(username, password);
            }
            conversation.command("MAIL FROM:<" + from + ">", "250");
            for (String recipient : recipients) {
                conversation.command("RCPT TO:<" + recipient + ">", "250", "251");
            }
            conversation.command("DATA", "354");
            conversation.write(message(subject, body));
            conversation.expect("250", "message body");
            conversation.command("QUIT", "221");
        }
    }

    private String message(String subject, String body) {
        StringBuilder out = new StringBuilder();
        out.append("Date: ").append(DATE.format(ZonedDateTime.now())).append("\r\n");
        out.append("From: ").append(from).append("\r\n");
        out.append("To: ").append(String.join(", ", recipients)).append("\r\n");
        out.append("Subject: ").append(header(subject)).append("\r\n");
        out.append("MIME-Version: 1.0\r\n");
        out.append("Content-Type: text/plain; charset=UTF-8\r\n");
        out.append("Content-Transfer-Encoding: base64\r\n\r\n");
        String encoded = Base64.getMimeEncoder().encodeToString(
                (body == null ? "" : body).getBytes(StandardCharsets.UTF_8));
        out.append(encoded).append("\r\n.\r\n");
        return out.toString();
    }

    private static String header(String value) {
        String flat = value == null ? "" : value.replace('\r', ' ').replace('\n', ' ').trim();
        return flat.isEmpty() ? "(no subject)" : flat;
    }

    private final class Conversation {

        private Socket socket;
        private BufferedReader reader;
        private BufferedWriter writer;

        private Conversation(Socket socket) throws IOException {
            this.socket = socket;
            this.reader = new BufferedReader(new InputStreamReader(socket.getInputStream(),
                    StandardCharsets.US_ASCII));
            this.writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(),
                    StandardCharsets.US_ASCII));
        }

        private String ehlo() throws IOException {
            command("EHLO ntd.local", "250");
            return lastReply;
        }

        private void authenticate(String user, String secret) throws IOException {
            command("AUTH LOGIN", "334");
            command(Base64.getEncoder().encodeToString(user.getBytes(StandardCharsets.UTF_8)), "334");
            command(Base64.getEncoder().encodeToString(secret.getBytes(StandardCharsets.UTF_8)), "235");
        }

        private void upgrade() throws IOException {
            SSLSocket secured = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault())
                    .createSocket(socket, host, port, true);
            secured.startHandshake();
            socket = secured;
            reader = new BufferedReader(new InputStreamReader(secured.getInputStream(),
                    StandardCharsets.US_ASCII));
            writer = new BufferedWriter(new OutputStreamWriter(secured.getOutputStream(),
                    StandardCharsets.US_ASCII));
        }

        private void write(String body) throws IOException {
            writer.write(body);
            writer.flush();
        }

        private void command(String line, String... accepted) throws IOException {
            write(line + "\r\n");
            lastReply = readReply();
            if (lastReply != null) {
                for (String code : accepted) {
                    if (lastReply.startsWith(code)) {
                        return;
                    }
                }
            }
            throw new IOException("smtp " + line + " replied " + lastReply);
        }

        private String lastReply = "";

        private void expect(String first, String step) throws IOException {
            lastReply = readReply();
            if (lastReply == null || !lastReply.startsWith(first)) {
                throw new IOException("smtp " + step + " replied " + lastReply);
            }
        }

        private String readReply() throws IOException {
            StringBuilder out = new StringBuilder();
            String line;
            do {
                line = reader.readLine();
                if (line == null) {
                    return null;
                }
                out.append(line).append(' ');
            } while (line.length() > 3 && line.charAt(3) == '-');
            return out.toString().trim();
        }
    }
}
