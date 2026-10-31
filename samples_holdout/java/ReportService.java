import java.io.BufferedReader;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Report generation (held-out smell fixture). */
public class ReportService {
    private static final int MAX_LINES = 1000;

    /** Read the lines of a report. */
    public List<String> read(Path path) {
        try (BufferedReader reader = Files.newBufferedReader(path)) {
            List<String> lines = new ArrayList<>();
            String line;
            while ((line = reader.readLine()) != null && lines.size() < MAX_LINES) {
                lines.add(line);
            }
            return lines;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Build a report title. */
    public String title(String kind, int year, int month, int day, boolean draft, boolean urgent) {  // EXPECT: LONG_PARAMETER_LIST
        String t = "";
        if (kind != null) {
            if (kind.equals("annual")) {
                if (draft) {
                    if (urgent) {
                        for (int i = 0; i < month; i++) {  // EXPECT: DEEP_NESTING
                            t += i;
                        }
                    }
                }
            }
        }
        return t + year + day;
    }

    /** Parse a flag. */
    public boolean isYes(String answer) {
        return answer == "yes";  // EXPECT: STRING_EQUALITY
    }

    /** Close quietly. */
    public void closeQuietly(AutoCloseable c) {
        try {
            c.close();
        } catch (Exception e) {  // EXPECT: BROAD_EXCEPT
            // nothing sensible to do here
        }
    }

    /** Percentage helper. */
    public double percent(int part, int total) {
        return part * 100.0 / total;
    }

    /** Tax helper. */
    public double withTax(double net) {
        return net * 1.19;  // EXPECT: MAGIC_NUMBER
    }
}
