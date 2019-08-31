package io.pointgenesis.utilities.security.hash;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.xml.bind.DatatypeConverter;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A one-way hash generator for the SHA-2 family of algorithms. The preferred hash mechanism is
 * shown in SecureHash.java. The fast hash methodology is provided for comparison only.
 * 
 * <ul>
 * <li>SHA-224</li>
 * <li>SHA-256</li>
 * <li>SHA-384</li>
 * <li>SHA-512</li>
 * <li>SHA-512/224</li>
 * <li>SHA-512/256</li>
 * </ul>
 * 
 * References:
 * [1] https://en.wikipedia.org/wiki/Secure_Hash_Algorithms
 * [2] https://www.mkyong.com/java/java-sha-hashing-example
 * [3] https://stackoverflow.com/questions/33085493/hash-a-password-with-sha-512-in-java
 * 
 * @author Travis L. Steinmetz
 *
 * Copyright 2019 Point Genesis Solutions, LLC
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
public class FastHash {
	private static final Logger log = LogManager.getLogger();
	
	/** Marked private to prevent unwanted instantiation. **/
	private FastHash() {
	}

	/**
	 * Generates a one-way hash from the given parameters.
	 * 
	 * @param value the clear-text value to hash.
	 * @param salt the salt to apply while generating the hash. 
	 * 
	 * @return the hashed representation of {@code}value + "." + {@code}salt.
	 */
	public static String getHash(final String value, final String salt) {
		String DEFAULT_HASH_ALGORITHM = "SHA-512";
		return getHash(value, salt, DEFAULT_HASH_ALGORITHM);
	}
	
	/**
	 * Generates a one-way hash from the given parameters.
	 * 
	 * @param value the clear-text value to hash.
	 * @param salt the salt to apply while generating the hash. 
	 * @param algorithm the SHA-2 algorithm that will be used to generate the hash.
	 * 
	 * @return the hashed representation of {@code}value + "." + {@code}salt.
	 */
	public static String getHash(final String value, final String salt, final String algorithm) {
		byte[] bytes = null;
		
		try {
			MessageDigest md = MessageDigest.getInstance(algorithm);
			md.update(DatatypeConverter.parseHexBinary(salt));
			
			bytes = md.digest(value.getBytes(StandardCharsets.UTF_8));
			log.debug("hashed value: {}", DatatypeConverter.printHexBinary(bytes));
		} catch (NoSuchAlgorithmException e) {
			String valueAsHex = null;
			if (value != null) {
				valueAsHex = DatatypeConverter.printHexBinary(value.getBytes(StandardCharsets.UTF_8));
			}
			log.error("Error encountered while generating hash. value: {} | salt: {} | algorithm: {}", valueAsHex, salt, algorithm);
			throw new IllegalArgumentException("Error encountered while generating hash");
		}
		
		return DatatypeConverter.printHexBinary(bytes) + "." + salt;
	}
	
	/**
	 * Compares a previously hashed value to another value that is hashed with the same
	 * salt value as the previously hashed value. If the resulting hash values are equal, 
	 * then the provided input matches the previously pre-hashed value.
	 * 
	 * @param rawValue the plain-text value to hash and compare against a previously hashed value.
	 * @param hashedValueAndSalt the previously hashed value and the salt used in the hash operation.
	 * 
	 * @return true if the hashed values are equal, otherwise false.
	 */
	public static boolean compare(String rawValue, String hashedValueAndSalt) {
		String[] values = hashedValueAndSalt.split("\\.");
		
		if (values.length != 2) {
			log.error("Expected exactly two tokens. But found {} tokens in hashedValueAndSalt: {}.", values.length, hashedValueAndSalt);
			throw new IllegalArgumentException("Incorrect number of tokens found in \"hashedValueAndSalt\" value.");
		}
		
		String hashedValue = values[0];
		String saltValue = values[1];
		
		String generatedHashAndSalt = getHash(rawValue, saltValue);
		
		String[] generatedValues = generatedHashAndSalt.split("\\.");
		String generatedHash = generatedValues[0];
		
		log.debug("Generated hash: {}", generatedHash);
		
		return hashedValue.contentEquals(generatedHash);
	}
}