
import static org.junit.Assert.assertEquals;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.junit.Test;

public class TestSymmmetricEncyption {
	
	@Test
	public void generateARandomAesKey() throws Exception{
				
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(256);
		
		SecretKey key = keyGenerator.generateKey();
		
		
		System.out.println(new String(key.getEncoded()));
		
		assertEquals("AES", key.getAlgorithm());
		assertEquals(32, key.getEncoded().length); //32 bytes or 256 bits key length.
		
	}
	
	@Test
	public void encryptAMessageWithAes() throws Exception
	{
		String message = "Alice knowsBob's secret";
		
		//Symmetric Encryption - Secret Key
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(256);
		SecretKey key = keyGenerator.generateKey();
		
		
		//Symmetric Encryption - IvParameterSpec
		SecureRandom secureRandom = new SecureRandom();
		byte[] ivBytes = new byte[16];
		secureRandom.nextBytes(ivBytes);
		IvParameterSpec iv = new IvParameterSpec(ivBytes);
		
		byte[] ciphertext = encryptWithAes(message, key, iv);
		String actualMessage = decryptWithAes(ciphertext, key, iv);
		
		assertEquals(message, actualMessage);
		
	}

	

	private byte[] encryptWithAes(String message, SecretKey key, IvParameterSpec iv) throws Exception {
		
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		CipherOutputStream cipherOutputStream = new CipherOutputStream(byteArrayOutputStream, cipher);
		OutputStreamWriter writer = new OutputStreamWriter(cipherOutputStream);
		try{
			writer.write(message);
		}finally{
			writer.close();
		}
		
		return byteArrayOutputStream.toByteArray();
	}
	
	private String decryptWithAes(byte[] ciphertext, SecretKey key, IvParameterSpec iv) throws Exception {
		
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, key, iv);
		
		ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(ciphertext);
		CipherInputStream cipherInputStream = new CipherInputStream(byteArrayInputStream, cipher);
		InputStreamReader inputStreamReader = new InputStreamReader(cipherInputStream);
		BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
		try{
			return bufferedReader.readLine();
		}finally{
			bufferedReader.close();
		}
	}

}
