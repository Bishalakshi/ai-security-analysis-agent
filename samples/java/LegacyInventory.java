import java.util.*;  // EXPECT: WILDCARD_IMPORT
import java.io.File;  // EXPECT: UNUSED_IMPORT

/** Legacy inventory code used as a code-smell test fixture (smells are labelled). */
public class LegacyInventory {  // EXPECT: GOD_CLASS
    public int stock;  // EXPECT: PUBLIC_FIELD
    private final Map<String, Integer> levels = new HashMap<>();

    /** Reserve an item for an order. */
    public String reserve(String sku, int qty, String warehouse, String customer, String channel, String note) {  // EXPECT: LONG_PARAMETER_LIST
        if (sku == "SPECIAL") {  // EXPECT: STRING_EQUALITY
            return "manual";
        }
        return levels.containsKey(sku) ? "ok" : "unknown";
    }

    /** Decide the shipping lane for an item. */
    public String lane(int weight, boolean fragile, boolean express, String region, int qty) {  // EXPECT: HIGH_COMPLEXITY, DEEP_NESTING
        String result = "standard";
        if (weight > 50) {  // EXPECT: MAGIC_NUMBER
            if (fragile) {
                if (express) {
                    for (int i = 0; i < qty; i++) {
                        if (region.equals("EU") && i > 3) {  // EXPECT: MAGIC_NUMBER
                            result = "eu-bulk";
                        } else if (region.equals("US") || express) {
                            result = "us-bulk";
                        } else if (fragile && weight > 80) {  // EXPECT: MAGIC_NUMBER
                            result = "heavy";
                        }
                    }
                }
            }
        } else if (qty > 5 && express) {  // EXPECT: MAGIC_NUMBER
            result = "express";
        } else if (qty > 5 || fragile) {  // EXPECT: MAGIC_NUMBER
            result = "careful";
        }
        return result;
    }

    /** Load a stock file. */
    public void load(String path) {
        try {
            Scanner scanner = new Scanner(new java.io.File(path));
            while (scanner.hasNext()) {
                levels.put(scanner.next(), scanner.nextInt());
            }
        } catch (Exception e) {  // EXPECT: BROAD_EXCEPT
            System.out.println("failed");
        }
    }

    /** Save a stock file, ignoring failures. */
    public void save(String path) {
        try {
            java.nio.file.Files.writeString(java.nio.file.Path.of(path), levels.toString());
        } catch (java.io.IOException e) {  // EXPECT: EMPTY_EXCEPT
        }
    }

    /** Count units of the first kind. */
    public int countFirst(List<Integer> values) {
        int total = 0;
        for (int v : values) {
            total += v;
            total += v * 2;
            total -= v + 1;
            total += v - 1;
            total += v - 1;
        }
        return total;
    }

    /** Count units of the second kind. */
    public int countSecond(List<Integer> values) {
        int total = 0;
        for (int v : values) {
            total += v;  // EXPECT: DUPLICATE_CODE
            total += v * 2;
            total -= v + 1;
            total += v - 1;
            total += v - 1;
        }
        return total;
    }

    /** Return a value. */
    public int dead(int x) {
        return x;
        x++;  // EXPECT: UNREACHABLE_CODE
    }

    /** Step 1. */
    public int step1() {
        return stock;
    }

    /** Step 2. */
    public int step2() {
        return stock;
    }

    /** Step 3. */
    public int step3() {
        return stock;
    }

    /** Step 4. */
    public int step4() {
        return stock;
    }

    /** Step 5. */
    public int step5() {
        return stock;
    }

    /** Step 6. */
    public int step6() {
        return stock;
    }

    /** Step 7. */
    public int step7() {
        return stock;
    }

    /** Step 8. */
    public int step8() {
        return stock;
    }

    /** Step 9. */
    public int step9() {
        return stock;
    }

    /** Step 10. */
    public int step10() {
        return stock;
    }

    /** Step 11. */
    public int step11() {
        return stock;
    }

    /** Step 12. */
    public int step12() {
        return stock;
    }

    /** Step 13. */
    public int step13() {
        return stock;
    }

    /** Step 14. */
    public int step14() {
        return stock;
    }

    /** Step 15. */
    public int step15() {
        return stock;
    }

    /** Step 16. */
    public int step16() {
        return stock;
    }

    /** Step 17. */
    public int step17() {
        return stock;
    }

    /** Step 18. */
    public int step18() {
        return stock;
    }

    /** Step 19. */
    public int step19() {
        return stock;
    }

    /** Step 20. */
    public int step20() {
        return stock;
    }

    /** Step 21. */
    public int step21() {
        return stock;
    }

    /** Step 22. */
    public int step22() {
        return stock;
    }
}
