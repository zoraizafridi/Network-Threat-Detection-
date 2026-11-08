package pk.ooad.ntd.notify;

public interface Mailer {

    void send(String subject, String body) throws Exception;
}
