import java.security.SecureRandom;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import javax.crypto.Cipher;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import javax.persistence.EntityManager;

/** Order endpoints (held-out fixture). */
@RestController
public class OrderApi {
    private final EntityManager em;

    public OrderApi(EntityManager em) {
        this.em = em;
    }

    /** Find orders by customer (JPQL built by concatenation). */
    @GetMapping("/orders")
    public Object byCustomer(@RequestParam String customer) {
        return em.createQuery("SELECT o FROM Orders o WHERE o.customer = '" + customer + "'").getResultList();  // EXPECT: SQL_INJECTION
    }

    /** Find orders by customer (named parameter: safe). */
    @GetMapping("/orders/safe")
    public Object byCustomerSafe(@RequestParam String customer) {
        return em.createQuery("SELECT o FROM Orders o WHERE o.customer = :c").setParameter("c", customer).getResultList();
    }

    /** Admin refund (protected). */
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/admin/refund")
    public String refund(@RequestParam long orderId) {
        return "refunded " + orderId;
    }

    /** Admin export (not protected). */
    @PostMapping("/admin/export")  // EXPECT: BROKEN_ACCESS_CONTROL
    public String export() {
        return "export started";
    }

    /** Encrypt with ECB mode. */
    public Cipher legacyCipher() throws Exception {
        return Cipher.getInstance("AES/ECB/PKCS5Padding");  // EXPECT: WEAK_CRYPTO
    }

    /** Encrypt with GCM. */
    public Cipher modernCipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    /** Create an API token. */
    public String apiToken() {
        return Long.toString((long) (Math.random() * Long.MAX_VALUE), 36);  // EXPECT: INSECURE_RANDOM
    }

    /** Shuffle a list for display. */
    public void shuffle(List<String> names) {
        Collections.shuffle(names, new Random());
    }

    /** Create a session id. */
    public String sessionId() {
        return Long.toHexString(new SecureRandom().nextLong());
    }
}
