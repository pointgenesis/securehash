package io.pointgenesis.utilities.security.hash;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Test;

public class SecureHashTest {
	private static final Logger log = LogManager.getLogger();

	@Test
	public void test_32_byte_hash_generation() {
		try {
			String saltAsHexString = "DFE0247EA7180ABBFB0E941DCF1B27ECEDFACF382BEFA2766720022196E98A8B";
			
			String password = "someRidiculous1394!&";
			log.debug("password: {}", password);

			String hashAsHexString = SecureHash.getHash(password, saltAsHexString);
			log.debug("hashAsHexString: {}", hashAsHexString);

			String expectedHexString = "95CDF380C587E955997CFF1115309EA5499EF422168CEC7E1D52AB1FB6CC088A";
			log.debug("Expected hash value as hex string: {}", expectedHexString);
			
			log.debug("Are hash values equal: {}", expectedHexString.equals(hashAsHexString));
			assertTrue(expectedHexString.equals(hashAsHexString));
		} catch (Exception e) {
			log.error("Error hashing password: {}", e.getMessage(), e);
			fail("Unable to verify that a known password and salt are hashed to the expected value.");
		}
	}
	
	@Test
	public void test_64_byte_hash_generation() {
		try {
			String saltAsHexString = "BAF52CD6CB68772D462BF1508E85D9EC5AE3B332A47CA7CE5F885D2618C30823B8C006A0AEB05746DE8F55CFE32BB451432A78AC3927307B6ED7F0802DCE8B83";

			String password = "someRidiculous1394!&";
			log.debug("password: {}", password);

			String hashAsHexString = SecureHash.getHash(password, saltAsHexString);
			log.debug("hashAsHexString: {}", hashAsHexString);

			String expectedHexString = "7489FCDBBB19FF60962F420A71C53B368FC5C940F9671CDF8FF3F7A1BEB39230";
			log.debug("Expected hash value as hex string: {}", expectedHexString);

			log.debug("Are hash values equal: {}", expectedHexString.equals(hashAsHexString));
			assertTrue(expectedHexString.equals(hashAsHexString));
		} catch (Exception e) {
			log.error("Error hashing password: {}", e.getMessage(), e);
			fail("Unable to verify that a known password and salt are hashed to the expected value.");
		}
	}
}
