package io.pointgenesis.utilities.security.salt;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import javax.xml.bind.DatatypeConverter;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Test;

public class SaltTest {
	private static final Logger log = LogManager.getLogger();
	
	@Test
	public void testGetSalt() {
		try {
			String saltAsHexString = Salt.getSalt();
			assertNotNull(saltAsHexString, "Salt is null.");
			
			byte[] saltAsBytes = DatatypeConverter.parseHexBinary(saltAsHexString);
			log.debug("saltAsBytes length: {}", saltAsBytes.length);
			assertTrue("Salt is not at least 64 bytes in length.", saltAsBytes.length >= 64);
		} catch (Exception e) {
			log.error("Salt was not generated.", e);
			fail("Salt was not generated.");
		}
	}
}
