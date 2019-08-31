# securehash
Demonstration of basic SHA2 and PBKDF2WithHmacSHA512 hashing as well as how to generate a salt and use with hashing methods.

## FashHash.java

An academic example of hashing using the SHA2 family of hashing algorithms including: 

  <ul>
  <li>SHA-224</li>
  <li>SHA-256</li>
  <li>SHA-384</li>
  <li>SHA-512</li>
  <li>SHA-512/224</li>
  <li>SHA-512/256</li>
  </ul>

The *SHA-512* algorithm is selected if no algorithm is provided.

The default provider is selected as *SUN* if no provider is given.

## SecureHash.java

Implements the PBKDF2 key stretching algorithm, which is a processor intensive operation designed to thwart brute-force attacks that are more likely to be successful against the fast hashing algoritms of the SHA2 family.
## Salt.java

Demonstrates the use of SecureRandom to generate a 64 byte (512 bit) secure random salt using the default *SHA1PRNG* algorithm if no algorithm is provided by the user.
## Logging via Log4j

# JUnit

Test cases deomonstrate the comparison of previously hashed values against a newly provided value that is hashed in conjunction of the previously used salt to generate a new hash value that is compared to the saved value for equality.

## References
[1] https://www.owasp.org/index.php/Hashing_Java

[2] https://en.wikipedia.org/wiki/Secure_Hash_Algorithms

[3] https://www.mkyong.com/java/java-sha-hashing-example

[4] https://stackoverflow.com/questions/33085493/hash-a-password-with-sha-512-in-java

[5] https://en.wikipedia.org/wiki/PBKDF2

[6] https://www.owasp.org/index.php/Cryptographic_Storage_Cheat_Sheet 

[7] https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet 

[8] https://www.darkreading.com/safely-storing-user-passwords-hashing-vs-encrypting/a/d-id/1269374? 

[9] https://www.mssqltips.com/sqlservertip/3293/add-a-salt-with-the-sql-server-hashbytes-function/ 

[10] https://www.owasp.org/index.php/Key_Management_Cheat_Sheet 

[11] https://safenet.gemalto.com/data-encryption/hardware-security-modules-hsms/ 

[12] https://docs.microsoft.com/en-us/sql/t-sql/functions/hashbytes-transact-sql 

[13] https://www.mssqltips.com/sqlservertip/2144/an-overview-of-extended-events-in-sql-server-2008/ 

[14] https://www.securityinnovationeurope.com/blog/page/whats-the-difference-between-hashing-and-encrypting 

[15] http://project-rainbowcrack.com/table.htm 

[16] https://martinfowler.com/articles/web-security-basics.html
