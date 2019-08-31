/**
 * 
 */
package io.pointgenesis.utilities.security.salt;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

import javax.xml.bind.DatatypeConverter;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
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
public class Salt {
	private static final Logger log = LogManager.getLogger();
	
	/**
	 * Hidden to prevent instantiation.
	 */
	private Salt() {		
	}

	/**
	 * Generates a 64 byte aka 512 bit secure random salt based upon the default algorithm \"SHA1PRNG\" and provider \"SUN\"
	 * as currently recommended by OWASP.
	 * 
	 * @return the generated salt as a hex string.
	 */	
	public static String getSalt() {
		int DEFAULT_SALT_LENGTH = 64;
		return getSalt(DEFAULT_SALT_LENGTH);
	}
	
	/**
	 * Generates a secure random salt based upon the given <code>size</code>, the default algorithm \"SHA1PRNG\" and provider \"SUN\".
	 * 
	 * @param size the length of the returned salt
 	 * 
	 * @return the generated salt as a hex string.
	 */	
	public static String getSalt(final int size) {
		String DEFAULT_ALGORITHM = "SHA1PRNG";
		return getSalt(size, DEFAULT_ALGORITHM);
	}

	/**
	 * Generates a secure random salt based upon the given size and algorithm. Defaults provider to \"SUN\".
	 * 
	 * @param size the length of the returned salt
	 * @param algorithm the algorithm name used to generate the SecureRandom object.
 	 * 
	 * @return the generated salt as a hex string.
	 */
	public static String getSalt(final int size, final String algorithm) {
		String DEFAULT_PROVIDER = "SUN";
		return getSalt(size, algorithm, DEFAULT_PROVIDER);
	}
	
	/**
	 * Generates a secure random salt based upon the given size, algorithm, and provider.
	 * 
	 * @param size the length of the returned salt
	 * @param algorithm the algorithm name used to generate the SecureRandom object.
 	 * @param provider the algorithm provider's name.
 	 * 
	 * @return the generated salt as a hex string.
	 */
	public static String getSalt(final int size, final String algorithm, final String provider) {
		if (size < 64) {
			log.warn("The size (length) does not meet OWASP guidelines -> size: {}", size);
			throw new IllegalArgumentException("The size (length) does not meet OWASP guidelines.");
		}
		
		byte[] salt = new byte[size];
		
		try {
			SecureRandom secureRandom = null;
			
			if (provider == null || algorithm == null) {
				if (algorithm == null) {
					log.info("No algorithm was specified, so deferring to the system default provider/algorithm.");
					secureRandom = new SecureRandom();
				} else {
					log.debug("Generating a salt using the given -> algorithm: {}", algorithm);
					secureRandom = SecureRandom.getInstance(algorithm);
				}
			} else {
				log.debug("Generating a salt using the parameters -> algorithm: {} | provider: {}", algorithm, provider);
				secureRandom = SecureRandom.getInstance(algorithm, provider);
			}
			secureRandom.nextBytes(salt);
			log.debug("Generated the following salt -> byte[]: {} | Hex String: {}", salt, DatatypeConverter.printHexBinary(salt));
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			StringBuilder sb = new StringBuilder();
			
			Provider[] providers = Security.getProviders();
			
			for(Provider availableProvider : providers) {
				sb.append(availableProvider.getName());
			}
			
			log.error(
					"Unable to generate a salt with the given parameters. algorithm: {} | provider: {} | size: {} | Available providers: {}", 
					algorithm, 
					provider, 
					size, 
					sb.toString());
			throw new IllegalArgumentException("Unable to generate a salt with the given parameters.");
		}
		return DatatypeConverter.printHexBinary(salt);
	}
}
