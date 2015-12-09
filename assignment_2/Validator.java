import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

class Validator {

  private static final BigInteger P = new BigInteger("b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323", 16);
  private static final BigInteger P_1 = P.subtract(BigInteger.ONE);
  private static final BigInteger G = new BigInteger("44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68", 16);

  public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
    if (args.length != 4) {
      System.out.println("Usage: java Validator filePath y r s");
      return;
    }

    File file = new File(args[0]);
    BigInteger y = new BigInteger(args[1], 16);
    BigInteger r = new BigInteger(args[2], 16);
    BigInteger s = new BigInteger(args[3], 16);

    System.out.printf("Checking that 0 < r: %b\n", r.compareTo(BigInteger.ZERO) > 0);
    System.out.printf("Checking that r < p: %b\n", r.compareTo(P) < 0);

    System.out.printf("Checking that 0 < s: %b\n", s.compareTo(BigInteger.ZERO) > 0);
    System.out.printf("Checking that s < p-1: %b\n", s.compareTo(P_1) < 0);

    MessageDigest sha = MessageDigest.getInstance("SHA-256");

    byte[] fileData = new byte[(int) file.length()];
    System.out.println(fileData.length);
    DataInputStream inputStream = new DataInputStream(new FileInputStream(file));
    inputStream.readFully(fileData);
    inputStream.close();

    BigInteger fileHash = new BigInteger(sha.digest(fileData));

    BigInteger leftSide = G.modPow(fileHash, P);
    BigInteger rightSide = y.modPow(r, P).multiply(r.modPow(s, P)).mod(P);

    System.out.printf("Checking that g^(H(m)) (mod p) = (y^r)(r^s) (mod p): %b\n", leftSide.equals(rightSide));
  }

}
