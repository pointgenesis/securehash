package io.pointgenesis.utilities.security.hash;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Generates a hash following the OWASP recommended practices for password hashing.
 * 
 * References:
 * 
 * [1] https://www.owasp.org/index.php/Hashing_Java
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

public class SecureHash {
	private static final Logger log = LogManager.getLogger();
	
	/** Marked private to prevent outside instantiation. **/
	private SecureHash() {
	}

	/**
	 * Generates a one-way hash from the given inputs.
	 * 
	 * @param value the clear text value to transform.
	 * @param salt the salt value to apply while hashing {@code}value.
	 * 
	 * @return the hashed representation of {@code}value.
	 */
	public static String getHash(final String value, final String salt) {
		int DEFAULT_ITERATIONS = 65536;
		return getHash(value, salt, DEFAULT_ITERATIONS);
	}
	
	/**
	 * Generates a one-way hash from the given inputs.
	 * 
	 * @param value the clear text value to transform.
	 * @param salt the salt value to apply while hashing {@code}value.
	 * @param iterations the number of hash iterations to execute against {@code}value.
	 * 
	 * @return the hashed representation of {@code}value.
	 */
	public static String getHash(final String value, final String salt, final int iterations) {
		int DEFAULT_LENGTH = 256;
		return getHash(value, salt, iterations, DEFAULT_LENGTH);
	}
	
	/**
	 * Generates a one-way hash from the given inputs.
	 * 
	 * @param value the clear text value to transform.
	 * @param salt the salt value to apply while hashing {@code}value.
	 * @param iterations the number of hash iterations to execute against {@code}value.
	 * @param length the key length.
	 * 
	 * @return the hashed representation of {@code}value.
	 */
	public static String getHash(
			final String value, final String salt, 
			final int iterations, final int length) {
		String DEFAULT_ALGORITHM = "PBKDF2WithHmacSHA512";
		return getHash(value, salt, iterations, length, DEFAULT_ALGORITHM);
	}
	
	/**
	 * Generates a one-way hash from the given inputs.
	 * 
	 * @param value the clear text value to transform.
	 * @param salt the salt value to apply while hashing {@code}value.
	 * @param iterations the number of hash iterations to execute against {@code}value.
	 * @param length the key length.
	 * @param algorithm the algorithm used in the hash generation.
	 * 
	 * @return the hashed representation of {@code}value.
	 */
	public static String getHash(
			final String value, final String salt, 
			final int iterations, final int length, final String algorithm) {
		boolean isValidInput = true;
		
		if (value == null || value.isEmpty()) {
			isValidInput = false;
			log.error("\"value\" cannot be null or empty.");
		}
		
		if (salt == null || salt.isEmpty()) {
			isValidInput = false;
			log.error("\"salt\" cannot be null or empty.");
		}
		
		if (algorithm == null || algorithm.isEmpty()) {
			isValidInput = false;
			log.error("\"algorithm\" cannot be null or empty.");
		}
		
		try {
			if (isValidInput == false) {
				throw new IllegalArgumentException("One or more inputs do not conform to the expected format.");
			}
			
			SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm);
			PBEKeySpec spec = new PBEKeySpec(value.toCharArray(), DatatypeConverter.parseHexBinary(salt), iterations, length);
			SecretKey key = skf.generateSecret(spec);
			
			return DatatypeConverter.printHexBinary(key.getEncoded());
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			String valueAsString = null;
			if (value != null) {
				valueAsString = new String(value);
				try {
					/*Obfuscate the value passed into the method for security purposes.*/
					valueAsString = DatatypeConverter.printHexBinary(valueAsString.getBytes());
				} catch (Exception ex) {
					log.warn("Unable to convert given \"value\" to hex binary format.");
				}
			}
			log.error(
					"Unable to compute hash of the following inputs -> value: {} | salt: {} | iterations: {} | length: {} | algorithm: {}",
					valueAsString, salt, iterations, length, algorithm);
			throw new IllegalArgumentException("Unable to generate a hash using the provided inputs.", e);
		}
	}
	
}
