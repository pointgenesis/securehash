package io.pointgenesis.utilities.security.hash;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Test;

public class FastHashTest {
	private static Logger log = LogManager.getLogger();

	@Test
	public void test_fast_hash_generation() {
		try {
			// String saltAsHexString = "DFE0247EA7180ABBFB0E941DCF1B27ECEDFACF382BEFA2766720022196E98A8B";
			String saltAsHexString = "0CB74D999566A3933BBA16E46B318F96AA3C2B5C0F8B7536B2C00592406BAD3317DE6D2820E17E68F7C66DB60140AF75F7530F16B3F496A7F6E79CA7CA1E35E5";
			String password = "myP@55w0Rd";

			// String expectedHashValue = "C606D415D6BA690166F8B69EE1B2A15C4223D0B20B8837D21648F2AF7C56A0DF7EE6BE25E95D452F6A240AB24EDE27958FB6015FCC0E4B5D6AD112B7125F3DF5";
			String expectedHashValue = "B27AC33E06630357EFE228E7B1F6A4C8242606DBFC55CBED4299E4F1FCC06ED0825A469B406E0BFDB7DAAA8C2FC876BB57130BA6DC51013F6E913BC8BE031643";

			boolean isMatching = FastHash.compare(password, (expectedHashValue + "." + saltAsHexString));

			log.debug("Does the generated hash match the stored/expected value: {}", isMatching);
			assertTrue("Generated hash does not match expected value.", isMatching);

		} catch (Exception e) {
			log.error("Unexpected error encountered while generating a SHA-2 family hash. {}", e.getMessage(), e);
			fail("Unexpected error encountered while generating a SHA-2 family hash.");
		}
	}
}
