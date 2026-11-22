import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDate;
import java.time.YearMonth;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;

// =====================================================================
//  CUSTOM EXCEPTIONS
// =====================================================================
class ShoppingException extends Exception {
    ShoppingException(String message) { super(message); }
}
class ValidationException extends ShoppingException {
    ValidationException(String message) { super(message); }
}
class AuthenticationException extends ShoppingException {
    AuthenticationException(String message) { super(message); }
}
class OutOfStockException extends ShoppingException {
    OutOfStockException(String message) { super(message); }
}
class PaymentException extends ShoppingException {
    PaymentException(String message) { super(message); }
}
class ReturnNotAllowedException extends ShoppingException {
    ReturnNotAllowedException(String message) { super(message); }
}

// =====================================================================
//  SECURITY UTILITY  (NFR1)
// =====================================================================
final class SecurityUtil {
    private static final SecureRandom RNG = new SecureRandom();
    private static final SecretKey AES_KEY = createKey();

    private SecurityUtil() { }

    private static SecretKey createKey() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(128);
            return kg.generateKey();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES not available", e);
        }
    }

    /** Random salt for password hashing. */
    static String newSalt() {
        byte[] b = new byte[16];
        RNG.nextBytes(b);
        return Base64.getEncoder().encodeToString(b);
    }

    /** Salted PBKDF2 hash - the plain password is never stored. */
    static String hashPassword(String password, String salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(),
                    Base64.getDecoder().decode(salt), 65536, 256);
            SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return Base64.getEncoder().encodeToString(f.generateSecret(spec).getEncoded());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Hashing failed", e);
        }
    }

    /** Constant-time comparison to avoid timing attacks. */
    static boolean safeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8));
    }

    /** AES-GCM encryption of payment credentials. */
    static String encrypt(String plain) {
        try {
            byte[] iv = new byte[12];
            RNG.nextBytes(iv);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, AES_KEY, new GCMParameterSpec(128, iv));
            byte[] enc = c.doFinal(plain.getBytes(StandardCharsets.UTF_8));
            byte[] all = new byte[iv.length + enc.length];
            System.arraycopy(iv, 0, all, 0, iv.length);
            System.arraycopy(enc, 0, all, iv.length, enc.length);
            return Base64.getEncoder().encodeToString(all);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Encryption failed", e);
        }
    }

    static String decrypt(String cipherText) {
        try {
            byte[] all = Base64.getDecoder().decode(cipherText);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, AES_KEY, new GCMParameterSpec(128, all, 0, 12));
            return new String(c.doFinal(all, 12, all.length - 12), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Decryption failed", e);
        }
    }
}

// =====================================================================
//  INPUT VALIDATION HELPERS
// =====================================================================
final class Validator {
    private static final Pattern EMAIL = Pattern.compile("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    private static final Pattern PHONE = Pattern.compile("^[6-9][0-9]{9}$");
    private static final Pattern PINCODE = Pattern.compile("^[1-9][0-9]{5}$");
    private static final Pattern UPI = Pattern.compile("^[A-Za-z0-9._-]{2,}@[A-Za-z]{2,}$");

    private Validator() { }

    static boolean isBlank(String s) { return s == null || s.trim().isEmpty(); }
    static boolean validEmail(String s) { return s != null && EMAIL.matcher(s).matches(); }
    static boolean validPhone(String s) { return s != null && PHONE.matcher(s).matches(); }
    static boolean validPincode(String s) { return s != null && PINCODE.matcher(s).matches(); }
    static boolean validUpi(String s) { return s != null && UPI.matcher(s).matches(); }

    /** Min 8 chars, at least one letter and one digit. */
    static boolean strongPassword(String p) {
        if (p == null || p.length() < 8) return false;
        boolean letter = false, digit = false;
        for (char ch : p.toCharArray()) {
            if (Character.isLetter(ch)) letter = true;
            if (Character.isDigit(ch)) digit = true;
        }
        return letter && digit;
    }

    /** Luhn checksum for card numbers. */
    static boolean luhn(String number) {
        int sum = 0;
        boolean alt = false;
        for (int i = number.length() - 1; i >= 0; i--) {
            int n = number.charAt(i) - '0';
            if (alt) { n *= 2; if (n > 9) n -= 9; }
            sum += n;
            alt = !alt;
        }
        return sum % 10 == 0;
    }
}

// =====================================================================
//  ADDRESS  (FR3)
// =====================================================================
class Address {
    private String line1, city, state, pincode;

    Address(String line1, String city, String state, String pincode) throws ValidationException {
        validate(line1, city, state, pincode);
        this.line1 = line1.trim();
        this.city = city.trim();
        this.state = state.trim();
        this.pincode = pincode.trim();
    }

    private static void validate(String line1, String city, String state, String pincode)
            throws ValidationException {
        if (Validator.isBlank(line1)) throw new ValidationException("Address line cannot be empty.");
        if (Validator.isBlank(city)) throw new ValidationException("City cannot be empty.");
        if (Validator.isBlank(state)) throw new ValidationException("State cannot be empty.");
        if (!Validator.validPincode(pincode == null ? null : pincode.trim()))
            throw new ValidationException("Pincode must be a valid 6 digit number.");
    }

    /** Update is all-or-nothing: nothing changes if any value is invalid. */
    void update(String line1, String city, String state, String pincode) throws ValidationException {
        validate(line1, city, state, pincode);
        this.line1 = line1.trim();
        this.city = city.trim();
        this.state = state.trim();
        this.pincode = pincode.trim();
    }

    String getPincode() { return pincode; }

    @Override
    public String toString() { return line1 + ", " + city + ", " + state + " - " + pincode; }
}

// =====================================================================
//  CART  (FR6)
// =====================================================================
class CartItem {
    private final Product product;
    private int quantity;

    CartItem(Product product, int quantity) { this.product = product; this.quantity = quantity; }

    Product getProduct() { return product; }
    int getQuantity() { return quantity; }
    void setQuantity(int q) { this.quantity = q; }
    BigDecimal subtotal() { return product.getPrice().multiply(BigDecimal.valueOf(quantity)); }
}

class Cart {
    private final Map<Integer, CartItem> items = new LinkedHashMap<Integer, CartItem>();

    void add(Product p, int qty) throws ValidationException, OutOfStockException {
        if (qty <= 0) throw new ValidationException("Quantity must be at least 1.");
        CartItem existing = items.get(p.getId());
        int newQty = qty + (existing == null ? 0 : existing.getQuantity());
        if (newQty > p.getStock())
            throw new OutOfStockException("Only " + p.getStock() + " unit(s) of '" + p.getName() + "' available.");
        if (existing == null) items.put(p.getId(), new CartItem(p, qty));
        else existing.setQuantity(newQty);
    }

    /** Removes the whole line (qty == 0) or reduces by qty. */
    void remove(int productId, int qty) throws ValidationException {
        CartItem it = items.get(productId);
        if (it == null) throw new ValidationException("Product " + productId + " is not in your cart.");
        if (qty < 0) throw new ValidationException("Quantity cannot be negative.");
        if (qty == 0 || qty >= it.getQuantity()) items.remove(productId);
        else it.setQuantity(it.getQuantity() - qty);
    }

    List<CartItem> getItems() { return new ArrayList<CartItem>(items.values()); }
    boolean isEmpty() { return items.isEmpty(); }
    void clear() { items.clear(); }

    BigDecimal total() {
        BigDecimal t = BigDecimal.ZERO;
        for (CartItem i : items.values()) t = t.add(i.subtotal());
        return t;
    }
}

// =====================================================================
//  USER  (FR1, FR2)
// =====================================================================
class User {
    private static int counter = 1000;
    private final int id;
    private final String name, email, phone, salt, passwordHash;
    private final List<Address> addresses = new ArrayList<Address>();
    private final Cart cart = new Cart();
    private int failedAttempts = 0;

    User(String name, String email, String phone, String password) {
        this.id = ++counter;
        this.name = name.trim();
        this.email = email.trim().toLowerCase();
        this.phone = phone.trim();
        this.salt = SecurityUtil.newSalt();
        this.passwordHash = SecurityUtil.hashPassword(password, salt);
    }

    boolean passwordMatches(String password) {
        return SecurityUtil.safeEquals(passwordHash, SecurityUtil.hashPassword(password, salt));
    }

    int getId() { return id; }
    String getName() { return name; }
    String getEmail() { return email; }
    String getPhone() { return phone; }
    String getPasswordHash() { return passwordHash; }
    List<Address> getAddresses() { return addresses; }
    Cart getCart() { return cart; }
    int getFailedAttempts() { return failedAttempts; }
    void recordFailure() { failedAttempts++; }
    void resetFailures() { failedAttempts = 0; }
}

class AuthService {
    static final int MAX_ATTEMPTS = 3;
    private final Map<String, User> users = new LinkedHashMap<String, User>();
    private User current;

    /** FR1 */
    User register(String name, String email, String phone, String password) throws ValidationException {
        if (Validator.isBlank(name)) throw new ValidationException("Name cannot be empty.");
        if (!Validator.validEmail(email)) throw new ValidationException("Invalid email address.");
        if (!Validator.validPhone(phone)) throw new ValidationException("Phone must be a 10 digit Indian mobile number.");
        if (!Validator.strongPassword(password))
            throw new ValidationException("Password must be at least 8 characters with a letter and a digit.");
        String key = email.trim().toLowerCase();
        if (users.containsKey(key)) throw new ValidationException("An account with this email already exists.");
        User u = new User(name, email, phone, password);
        users.put(key, u);
        return u;
    }

    /** FR2 */
    User login(String email, String password) throws AuthenticationException {
        User u = (email == null) ? null : users.get(email.trim().toLowerCase());
        if (u == null || password == null) throw new AuthenticationException("Invalid email or password.");
        if (u.getFailedAttempts() >= MAX_ATTEMPTS)
            throw new AuthenticationException("Account locked after " + MAX_ATTEMPTS + " failed attempts.");
        if (!u.passwordMatches(password)) {
            u.recordFailure();
            throw new AuthenticationException("Invalid email or password.");
        }
        u.resetFailures();
        current = u;
        return u;
    }

    /** FR11 */
    void logout() { current = null; }
    boolean isLoggedIn() { return current != null; }
    User getCurrentUser() { return current; }
}

// =====================================================================
//  PRODUCTS  (FR4, FR5)  - abstraction + inheritance + polymorphism
// =====================================================================
abstract class Product {
    private final int id;
    private final String name, category, description;
    private final BigDecimal price;
    private int stock;

    Product(int id, String name, String category, String description, double price, int stock) {
        this.id = id;
        this.name = name;
        this.category = category;
        this.description = description;
        this.price = BigDecimal.valueOf(price);
        this.stock = stock;
    }

    /** Each subclass adds its own specific details. */
    protected abstract String extraDetails();

    /** FR5 */
    String getDetails() {
        return "ID          : " + id + "\n"
             + "Name        : " + name + "\n"
             + "Category    : " + category + "\n"
             + "Price       : " + Money.fmt(price) + "\n"
             + "In stock    : " + stock + "\n"
             + "Description : " + description + "\n"
             + extraDetails();
    }

    String summaryLine() {
        return String.format("%-4d %-26s %-12s %12s  (stock %d)", id, name, category, Money.fmt(price), stock);
    }

    void reduceStock(int q) throws OutOfStockException {
        if (q > stock) throw new OutOfStockException("Insufficient stock for '" + name + "'.");
        stock -= q;
    }
    void restock(int q) { stock += q; }

    int getId() { return id; }
    String getName() { return name; }
    String getCategory() { return category; }
    String getDescription() { return description; }
    BigDecimal getPrice() { return price; }
    int getStock() { return stock; }
}

class ElectronicsProduct extends Product {
    private final int warrantyMonths;
    ElectronicsProduct(int id, String name, String desc, double price, int stock, int warrantyMonths) {
        super(id, name, "Electronics", desc, price, stock);
        this.warrantyMonths = warrantyMonths;
    }
    @Override protected String extraDetails() { return "Warranty    : " + warrantyMonths + " months"; }
}

class ClothingProduct extends Product {
    private final String size, fabric;
    ClothingProduct(int id, String name, String desc, double price, int stock, String size, String fabric) {
        super(id, name, "Clothing", desc, price, stock);
        this.size = size;
        this.fabric = fabric;
    }
    @Override protected String extraDetails() { return "Size/Fabric : " + size + " / " + fabric; }
}

class GroceryProduct extends Product {
    private final String weight;
    private final int shelfLifeDays;
    GroceryProduct(int id, String name, String desc, double price, int stock, String weight, int shelfLifeDays) {
        super(id, name, "Grocery", desc, price, stock);
        this.weight = weight;
        this.shelfLifeDays = shelfLifeDays;
    }
    @Override protected String extraDetails() { return "Weight/Shelf : " + weight + " / " + shelfLifeDays + " days"; }
}

class ProductCatalog {
    private final Map<Integer, Product> products = new LinkedHashMap<Integer, Product>();

    ProductCatalog() {
        add(new ElectronicsProduct(1, "Wireless Earbuds", "Bluetooth 5.3, 24h battery", 1999, 25, 12));
        add(new ElectronicsProduct(2, "Smart Watch", "1.8 inch display, heart-rate sensor", 3499, 10, 12));
        add(new ElectronicsProduct(3, "Power Bank 20000mAh", "Fast charging, dual USB", 1599, 40, 6));
        add(new ClothingProduct(4, "Cotton T-Shirt", "Regular fit, round neck", 599, 60, "M", "Cotton"));
        add(new ClothingProduct(5, "Denim Jeans", "Slim fit, stretchable", 1799, 30, "32", "Denim"));
        add(new ClothingProduct(6, "Running Shoes", "Lightweight mesh upper", 2499, 15, "9", "Mesh"));
        add(new GroceryProduct(7, "Basmati Rice", "Premium long grain", 649, 100, "5 kg", 365));
        add(new GroceryProduct(8, "Olive Oil", "Extra virgin", 899, 50, "1 L", 540));
        add(new GroceryProduct(9, "Green Tea", "25 tea bags", 199, 80, "50 g", 270));
        add(new ElectronicsProduct(10, "Limited Edition Camera", "Only two pieces left", 45999, 2, 24));
    }

    void add(Product p) { products.put(p.getId(), p); }

    /** FR4 - all products, optionally filtered by category / keyword. */
    List<Product> browse(String filter) {
        List<Product> out = new ArrayList<Product>();
        String f = (filter == null) ? "" : filter.trim().toLowerCase();
        for (Product p : products.values()) {
            if (f.isEmpty() || p.getCategory().toLowerCase().contains(f) || p.getName().toLowerCase().contains(f))
                out.add(p);
        }
        return out;
    }

    Product findById(int id) throws ValidationException {
        Product p = products.get(id);
        if (p == null) throw new ValidationException("No product found with ID " + id + ".");
        return p;
    }
}

final class Money {
    private Money() { }
    static String fmt(BigDecimal amount) { return String.format("Rs. %,.2f", amount); }
}

// =====================================================================
//  PAYMENTS  (FR8, NFR1.2) - abstraction + polymorphism
// =====================================================================
enum PaymentStatus { PENDING, COD_PENDING, PAID, REFUNDED }

abstract class Payment {
    private static int counter = 5000;
    private final BigDecimal amount;
    private final String transactionId;
    private PaymentStatus status = PaymentStatus.PENDING;

    Payment(BigDecimal amount) {
        this.amount = amount;
        this.transactionId = "TXN" + (++counter);
    }

    abstract String getMethodName();

    /** Validates and processes the payment, otherwise throws PaymentException. */
    abstract void process() throws PaymentException;

    /** Called when the courier delivers the parcel (COD is collected then). */
    void onDelivered() { if (status == PaymentStatus.COD_PENDING) status = PaymentStatus.PAID; }

    String refund() {
        status = PaymentStatus.REFUNDED;
        return "Refund of " + Money.fmt(amount) + " initiated to original payment method (" + getMethodName() + ").";
    }

    BigDecimal getAmount() { return amount; }
    String getTransactionId() { return transactionId; }
    PaymentStatus getStatus() { return status; }
    protected void setStatus(PaymentStatus s) { status = s; }
}

class CODPayment extends Payment {
    CODPayment(BigDecimal amount) { super(amount); }
    @Override String getMethodName() { return "Cash on Delivery"; }
    @Override void process() { setStatus(PaymentStatus.COD_PENDING); }
    @Override String refund() {
        super.refund();
        return "Refund of " + Money.fmt(getAmount()) + " will be sent to your bank account after return pickup (COD).";
    }
}

class CardPayment extends Payment {
    private final String encryptedNumber;   // card number is stored only in encrypted form
    private final String last4;
    private final String holder, expiry;    // CVV is never stored permanently
    private String numberTmp, cvvTmp;       // held only until process() finishes, then cleared

    CardPayment(BigDecimal amount, String number, String holder, String expiry, String cvv) {
        super(amount);
        String n = number == null ? "" : number.replaceAll("[\\s-]", "");
        this.numberTmp = n;
        this.cvvTmp = cvv == null ? "" : cvv;
        this.holder = holder == null ? "" : holder.trim();
        this.expiry = expiry == null ? "" : expiry.trim();
        this.last4 = n.length() >= 4 ? n.substring(n.length() - 4) : "";
        this.encryptedNumber = n.matches("[0-9]{13,19}") ? SecurityUtil.encrypt(n) : "";
    }

    @Override String getMethodName() { return "Card ending " + last4; }

    @Override void process() throws PaymentException {
        try {
            if (!numberTmp.matches("[0-9]{13,19}") || !Validator.luhn(numberTmp))
                throw new PaymentException("Invalid card number.");
            if (holder.isEmpty()) throw new PaymentException("Card holder name is required.");
            if (!cvvTmp.matches("[0-9]{3,4}")) throw new PaymentException("Invalid CVV.");
            YearMonth exp;
            try {
                exp = YearMonth.parse(expiry, DateTimeFormatter.ofPattern("MM/yy"));
            } catch (RuntimeException e) {
                throw new PaymentException("Expiry must be in MM/YY format.");
            }
            if (exp.isBefore(YearMonth.now())) throw new PaymentException("Card has expired.");
            setStatus(PaymentStatus.PAID);
        } finally {
            numberTmp = "";   // do not keep raw credentials in memory longer than needed
            cvvTmp = "";
        }
    }

    String getEncryptedNumber() { return encryptedNumber; }
    String getLast4() { return last4; }
}

class UPIPayment extends Payment {
    private final String upiId;
    UPIPayment(BigDecimal amount, String upiId) { super(amount); this.upiId = upiId == null ? "" : upiId.trim(); }
    @Override String getMethodName() { return "UPI (" + upiId + ")"; }
    @Override void process() throws PaymentException {
        if (!Validator.validUpi(upiId)) throw new PaymentException("Invalid UPI ID. Format: name@bank");
        setStatus(PaymentStatus.PAID);
    }
}

// =====================================================================
//  ORDERS  (FR7, FR9, FR10)
// =====================================================================
enum OrderStatus {
    PLACED, PACKED, SHIPPED, OUT_FOR_DELIVERY, DELIVERED, RETURN_REQUESTED, REFUNDED;

    /** Next stage of the courier/return pipeline, or null if finished. */
    OrderStatus next() {
        switch (this) {
            case PLACED: return PACKED;
            case PACKED: return SHIPPED;
            case SHIPPED: return OUT_FOR_DELIVERY;
            case OUT_FOR_DELIVERY: return DELIVERED;
            case RETURN_REQUESTED: return REFUNDED;
            default: return null;
        }
    }
}

class OrderLine {
    private final Product product;
    private final int quantity;
    private final BigDecimal unitPrice;   // price snapshot at purchase time

    OrderLine(Product product, int quantity) {
        this.product = product;
        this.quantity = quantity;
        this.unitPrice = product.getPrice();
    }
    Product getProduct() { return product; }
    int getQuantity() { return quantity; }
    BigDecimal subtotal() { return unitPrice.multiply(BigDecimal.valueOf(quantity)); }
    @Override public String toString() {
        return product.getName() + " x" + quantity + " = " + Money.fmt(subtotal());
    }
}

class Order {
    static final int RETURN_WINDOW_DAYS = 7;
    private static int counter = 9000;

    private final String orderId;
    private final List<OrderLine> lines;
    private final Address address;
    private final Payment payment;
    private final BigDecimal total;
    private final List<String> history = new ArrayList<String>();
    private OrderStatus status = OrderStatus.PLACED;
    private LocalDate deliveredOn;
    private String returnReason;

    Order(List<OrderLine> lines, Address address, Payment payment, BigDecimal total) {
        this.orderId = "ORD" + (++counter);
        this.lines = lines;
        this.address = address;
        this.payment = payment;
        this.total = total;
        log("Order placed");
    }

    private void log(String msg) { history.add(LocalDate.now() + "  " + status + " - " + msg); }

    /** FR9 - simulates a courier update (used by the demo option). */
    String advance() {
        OrderStatus next = status.next();
        if (next == null) return "No further updates for this order.";
        status = next;
        if (status == OrderStatus.DELIVERED) {
            deliveredOn = LocalDate.now();
            payment.onDelivered();
            log("Delivered to customer");
        } else if (status == OrderStatus.REFUNDED) {
            String msg = payment.refund();
            for (OrderLine l : lines) l.getProduct().restock(l.getQuantity());
            log(msg);
            return msg;
        } else {
            log("Status updated");
        }
        return "Order is now " + status;
    }

    /** FR10 */
    boolean isReturnEligible() {
        return status == OrderStatus.DELIVERED && deliveredOn != null
                && ChronoUnit.DAYS.between(deliveredOn, LocalDate.now()) <= RETURN_WINDOW_DAYS;
    }

    void requestReturn(String reason) throws ReturnNotAllowedException, ValidationException {
        if (Validator.isBlank(reason)) throw new ValidationException("Please give a reason for the return.");
        if (status == OrderStatus.RETURN_REQUESTED || status == OrderStatus.REFUNDED)
            throw new ReturnNotAllowedException("A return has already been requested for this order.");
        if (status != OrderStatus.DELIVERED)
            throw new ReturnNotAllowedException("Only delivered orders can be returned (current status: " + status + ").");
        if (!isReturnEligible())
            throw new ReturnNotAllowedException("Return window of " + RETURN_WINDOW_DAYS + " days has expired.");
        returnReason = reason.trim();
        status = OrderStatus.RETURN_REQUESTED;
        log("Return requested: " + returnReason);
    }

    /** Test helper: pretend the parcel was delivered some days ago. */
    void setDeliveredOnForTesting(LocalDate d) { this.deliveredOn = d; }

    String getOrderId() { return orderId; }
    OrderStatus getStatus() { return status; }
    Payment getPayment() { return payment; }
    BigDecimal getTotal() { return total; }
    List<OrderLine> getLines() { return lines; }
    List<String> getHistory() { return history; }
    String getReturnReason() { return returnReason; }

    String summary() {
        StringBuilder sb = new StringBuilder();
        sb.append("Order ").append(orderId).append("  [").append(status).append("]\n");
        for (OrderLine l : lines) sb.append("   - ").append(l).append("\n");
        sb.append("   Total   : ").append(Money.fmt(total)).append("\n");
        sb.append("   Payment : ").append(payment.getMethodName()).append(" (").append(payment.getStatus())
          .append(", ").append(payment.getTransactionId()).append(")\n");
        sb.append("   Ship to : ").append(address);
        return sb.toString();
    }
}

class OrderService {
    private final Map<String, List<Order>> ordersByUser = new LinkedHashMap<String, List<Order>>();

    /**
     * FR7 + FR8. Order of operations keeps data consistent:
     * validate stock -> take payment -> reduce stock -> save order -> empty cart.
     * If payment fails nothing else changes.
     */
    synchronized Order placeOrder(User user, Address address, Payment payment)
            throws ShoppingException {
        Cart cart = user.getCart();
        if (cart.isEmpty()) throw new ValidationException("Your cart is empty.");
        if (address == null) throw new ValidationException("Please add a delivery address first.");

        List<OrderLine> lines = new ArrayList<OrderLine>();
        for (CartItem ci : cart.getItems()) {
            if (ci.getQuantity() > ci.getProduct().getStock())
                throw new OutOfStockException("'" + ci.getProduct().getName() + "' no longer has enough stock.");
            lines.add(new OrderLine(ci.getProduct(), ci.getQuantity()));
        }
        payment.process();                                       // throws PaymentException on failure
        for (OrderLine l : lines) l.getProduct().reduceStock(l.getQuantity());
        Order order = new Order(lines, address, payment, cart.total());
        String key = user.getEmail();
        if (!ordersByUser.containsKey(key)) ordersByUser.put(key, new ArrayList<Order>());
        ordersByUser.get(key).add(order);
        cart.clear();
        return order;
    }

    List<Order> getOrders(User user) {
        List<Order> l = ordersByUser.get(user.getEmail());
        return l == null ? new ArrayList<Order>() : new ArrayList<Order>(l);
    }

    Order findOrder(User user, String orderId) throws ValidationException {
        for (Order o : getOrders(user))
            if (o.getOrderId().equalsIgnoreCase(orderId == null ? "" : orderId.trim())) return o;
        throw new ValidationException("No order '" + orderId + "' found in your account.");
    }
}

// =====================================================================
//  CONSOLE USER INTERFACE  (text only - no GUI)
// =====================================================================
public class ShoppingApp {
    private final Scanner in = new Scanner(System.in);
    private final AuthService auth = new AuthService();
    private final ProductCatalog catalog = new ProductCatalog();
    private final OrderService orders = new OrderService();
    private boolean running = true;

    public static void main(String[] args) {
        new ShoppingApp().run();
    }

    // ---- small input helpers (robust against bad input and end of input) ----
    private String ask(String prompt) {
        System.out.print(prompt);
        if (!in.hasNextLine()) { running = false; return ""; }   // input closed -> exit cleanly
        return in.nextLine().trim();
    }

    private int askInt(String prompt) {
        String s = ask(prompt);
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return -1;   // treated as an invalid choice by callers
        }
    }

    private void line() { System.out.println("--------------------------------------------------------------"); }

    private void run() {
        System.out.println("==============================================================");
        System.out.println("              ONLINE SHOPPING APP             ");
        System.out.println("==============================================================");
        while (running) {
            try {
                if (auth.isLoggedIn()) userMenu(); else guestMenu();
            } catch (ShoppingException e) {
                System.out.println("[!] " + e.getMessage());
            } catch (RuntimeException e) {          // last safety net: the app never crashes
                System.out.println("[!] Unexpected problem, please try again. (" + e.getClass().getSimpleName() + ")");
            }
        }
        System.out.println("Thank you for shopping with us. Goodbye!");
    }

    private void guestMenu() throws ShoppingException {
        line();
        System.out.println("1. Register   2. Login   3. Browse products   0. Exit");
        int c = askInt("Choice: ");
        if (!running) return;
        switch (c) {
            case 1: register(); break;
            case 2: login(); break;
            case 3: browse(); break;
            case 0: running = false; break;
            default: System.out.println("[!] Invalid choice.");
        }
    }

    private void userMenu() throws ShoppingException {
        line();
        System.out.println("Logged in as " + auth.getCurrentUser().getName());
        System.out.println(" 1. Browse products        2. View product details");
        System.out.println(" 3. Add product to cart    4. Remove product from cart");
        System.out.println(" 5. View cart              6. Manage address");
        System.out.println(" 7. Place order (checkout) 8. Track order");
        System.out.println(" 9. Request return/refund 10. My orders");
        System.out.println("11. Logout                 0. Exit");
        int c = askInt("Choice: ");
        if (!running) return;
        switch (c) {
            case 1: browse(); break;
            case 2: details(); break;
            case 3: addToCart(); break;
            case 4: removeFromCart(); break;
            case 5: viewCart(); break;
            case 6: manageAddress(); break;
            case 7: checkout(); break;
            case 8: track(); break;
            case 9: returnOrder(); break;
            case 10: myOrders(); break;
            case 11: auth.logout(); System.out.println("You have been logged out."); break;
            case 0: running = false; break;
            default: System.out.println("[!] Invalid choice.");
        }
    }

    // ---- FR1 ----
    private void register() throws ShoppingException {
        String name = ask("Full name : ");
        String email = ask("Email     : ");
        String phone = ask("Mobile    : ");
        String pass = ask("Password  : ");
        User u = auth.register(name, email, phone, pass);
        System.out.println("Registration successful. Your customer ID is " + u.getId() + ". Please login.");
    }

    // ---- FR2 ----
    private void login() throws ShoppingException {
        String email = ask("Email    : ");
        String pass = ask("Password : ");
        User u = auth.login(email, pass);
        System.out.println("Welcome back, " + u.getName() + "!");
    }

    // ---- FR4 ----
    private void browse() {
        String f = ask("Filter by category/name (press Enter for all): ");
        List<Product> list = catalog.browse(f);
        if (list.isEmpty()) { System.out.println("No products found."); return; }
        System.out.printf("%-4s %-26s %-12s %12s%n", "ID", "Name", "Category", "Price");
        for (Product p : list) System.out.println(p.summaryLine());
    }

    // ---- FR5 ----
    private void details() throws ShoppingException {
        int id = askInt("Product ID: ");
        System.out.println(catalog.findById(id).getDetails());
    }

    // ---- FR6 ----
    private void addToCart() throws ShoppingException {
        int id = askInt("Product ID: ");
        Product p = catalog.findById(id);
        int q = askInt("Quantity  : ");
        auth.getCurrentUser().getCart().add(p, q);
        System.out.println("Added to cart: " + p.getName() + " x" + q);
    }

    private void removeFromCart() throws ShoppingException {
        int id = askInt("Product ID to remove: ");
        int q = askInt("Quantity to remove (0 = remove completely): ");
        auth.getCurrentUser().getCart().remove(id, q);
        System.out.println("Cart updated.");
    }

    private void viewCart() {
        Cart cart = auth.getCurrentUser().getCart();
        if (cart.isEmpty()) { System.out.println("Your cart is empty."); return; }
        for (CartItem i : cart.getItems())
            System.out.printf("%-4d %-26s x%-3d %12s%n", i.getProduct().getId(), i.getProduct().getName(),
                    i.getQuantity(), Money.fmt(i.subtotal()));
        System.out.println("Cart total: " + Money.fmt(cart.total()));
    }

    // ---- FR3 ----
    private void manageAddress() throws ShoppingException {
        User u = auth.getCurrentUser();
        List<Address> list = u.getAddresses();
        for (int i = 0; i < list.size(); i++) System.out.println((i + 1) + ". " + list.get(i));
        System.out.println("A. Add new address   U. Update an address   B. Back");
        String c = ask("Choice: ").toUpperCase();
        if (c.equals("A")) {
            Address a = new Address(ask("Address line: "), ask("City: "), ask("State: "), ask("Pincode: "));
            list.add(a);
            System.out.println("Address added.");
        } else if (c.equals("U")) {
            int n = askInt("Address number to update: ");
            if (n < 1 || n > list.size()) throw new ValidationException("Invalid address number.");
            list.get(n - 1).update(ask("Address line: "), ask("City: "), ask("State: "), ask("Pincode: "));
            System.out.println("Address updated.");
        }
    }

    // ---- FR7 + FR8 ----
    private void checkout() throws ShoppingException {
        User u = auth.getCurrentUser();
        if (u.getCart().isEmpty()) throw new ValidationException("Your cart is empty.");
        if (u.getAddresses().isEmpty()) throw new ValidationException("Please add a delivery address first (menu 6).");
        viewCart();
        List<Address> list = u.getAddresses();
        for (int i = 0; i < list.size(); i++) System.out.println((i + 1) + ". " + list.get(i));
        int n = askInt("Deliver to address number: ");
        if (n < 1 || n > list.size()) throw new ValidationException("Invalid address number.");

        System.out.println("Payment method: 1. Cash on Delivery  2. Debit/Credit Card  3. UPI");
        int m = askInt("Choice: ");
        BigDecimal amount = u.getCart().total();
        Payment pay;
        if (m == 1) {
            pay = new CODPayment(amount);
        } else if (m == 2) {
            pay = new CardPayment(amount, ask("Card number : "), ask("Card holder : "),
                    ask("Expiry MM/YY: "), ask("CVV         : "));
        } else if (m == 3) {
            pay = new UPIPayment(amount, ask("UPI ID (name@bank): "));
        } else {
            throw new ValidationException("Invalid payment method.");
        }
        Order o = orders.placeOrder(u, list.get(n - 1), pay);
        System.out.println("Order placed successfully!");
        System.out.println(o.summary());
    }

    // ---- FR9 ----
    private void track() throws ShoppingException {
        Order o = orders.findOrder(auth.getCurrentUser(), ask("Order ID: "));
        for (String h : o.getHistory()) System.out.println("  * " + h);
        System.out.println("Current status: " + o.getStatus());
        String s = ask("Simulate next courier update (demo)? (y/n): ");
        if (s.equalsIgnoreCase("y")) System.out.println(o.advance());
    }

    // ---- FR10 ----
    private void returnOrder() throws ShoppingException {
        Order o = orders.findOrder(auth.getCurrentUser(), ask("Order ID: "));
        o.requestReturn(ask("Reason for return: "));
        System.out.println("Return requested for " + o.getOrderId()
                + ". Use 'Track order' to follow the pickup and refund.");
    }

    private void myOrders() {
        List<Order> l = orders.getOrders(auth.getCurrentUser());
        if (l.isEmpty()) { System.out.println("You have no orders yet."); return; }
        for (Order o : l) System.out.println(o.summary());
    }
}