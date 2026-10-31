package pk.ooad.ntd;

public class Main {
    public static void main(String[] args) {
        boolean headless = false;
        boolean web = false;
        for (String a : args) {
            if (a.equals("--headless")) headless = true;
            if (a.equals("--web")) web = true;
        }
        if (web) System.out.println("Web mode (to be built)");
        else if (headless) System.out.println("Headless mode (to be built)");
        else System.out.println("Swing mode (to be built)");
    }
}