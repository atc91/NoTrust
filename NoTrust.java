package co.atc91.notrust;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Christian
 */
public class NoTrust
{
    public static final String CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";

    public static final String CYPHER_KEY_ALGORITHM = "AES";

    public static final String PAIR_KEY_ALGORITHM = "RSA";

    public static final int PAIR_KEY_SIZE = 1024;

    public static final String SIGNATURE_ALGORITHM = "SHA512withRSA";

    public static final String RANDOM_ALGORITHM = "SHA1PRNG";

    public static void saveFile( byte[] data, String path ) throws FileNotFoundException, IOException
    {
        Files.write( Paths.get( path ), data );
    }

    public static byte[] readFile( String path ) throws FileNotFoundException, IOException
    {
        return Files.readAllBytes( Paths.get( path ) );
    }

    public static byte[] encrypt( byte[] keydata, byte[] data ) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, InvalidParameterSpecException
    {
        SecretKey secretKey = new SecretKeySpec( keydata, CYPHER_KEY_ALGORITHM );

        Cipher cipher = Cipher.getInstance( CIPHER_ALGORITHM );
        cipher.init( Cipher.ENCRYPT_MODE, secretKey );

        return cipher.doFinal( data );
    }

    public static byte[] decrypt( byte[] keydata, byte[] encriptedData ) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
    {
        SecretKey secretKey = new SecretKeySpec( keydata, CYPHER_KEY_ALGORITHM );

        Cipher cipher = Cipher.getInstance( CIPHER_ALGORITHM );
        cipher.init( Cipher.DECRYPT_MODE, secretKey );

        return cipher.doFinal( encriptedData );
    }

    public static PrivateKey decodePrivateKey( byte[] keydata ) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        //Estandar de codificacion de llaves privadas
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec( keydata );
        KeyFactory keyFactory = KeyFactory.getInstance( PAIR_KEY_ALGORITHM );

        return keyFactory.generatePrivate( privKeySpec );
    }

    public static PublicKey decodePublicKey( byte[] keydata ) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        //Estandar de codificacion de llaves publicas
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec( keydata );
        KeyFactory keyFactory = KeyFactory.getInstance( PAIR_KEY_ALGORITHM );

        return keyFactory.generatePublic( pubKeySpec );
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException
    {
        KeyPairGenerator generator = KeyPairGenerator.getInstance( PAIR_KEY_ALGORITHM );
        SecureRandom random = SecureRandom.getInstance( RANDOM_ALGORITHM );

        generator.initialize( PAIR_KEY_SIZE, random );

        return generator.generateKeyPair();
    }

    public static byte[] sign( PrivateKey privateKey, byte[] data ) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException
    {
        /*
         * Create a Signature object and initialize it with the private
         * key
         */
        Signature signature = Signature.getInstance( SIGNATURE_ALGORITHM );
        signature.initSign( privateKey );

        /*
         * Update the data
         */
        signature.update( data );

        /*
         * Now that all the data to be signed has been read in,
         * generate a signature for it
         */
        return signature.sign();
    }

    public static boolean verify( PublicKey publicKey, byte[] signatureData, byte[] data ) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException
    {
        /*
         * create a Signature object and initialize it with the public key
         */
        Signature signature = Signature.getInstance( SIGNATURE_ALGORITHM );
        signature.initVerify( publicKey );

        /*
         * Update and verify the data
         */
        signature.update( data );

        return signature.verify( signatureData );
    }

    public static void main( String[] args ) throws Exception
    {
        BufferedReader in = new BufferedReader( new InputStreamReader( System.in ) );

        String help = "Usage: NoTrust.jar [COMMAND] [ARGUMENTS]\n\t"
                      + "gen nameOfPrivateKey nameOfPublicKey\n\t"
                      + "sign nameOfPrivateKey nameOfTheSignature nameOfFileToSign \n\t"
                      + "ver nameOfPublicKey nameOfSignature nameOfFileToVerify";

        if( args.length == 0 )
        {
            System.out.println( help );
            return;
        }

        //Datos de entrada
        String privateKeyPath, publicKeyPath, fileToSignPath, signaturePath, fileToVerifyPath, password;

        String command = args[0];
        switch( command )
        {
            case "help":
                System.out.println( help );

                break;
            case "gen":
                privateKeyPath = args[1];
                publicKeyPath = args[2];

                System.out.print( "Enter password (16 letters): " );
                password = in.readLine();

                KeyPair pair = generateKeyPair();
                saveFile( encrypt( password.getBytes(), pair.getPrivate().getEncoded() ), privateKeyPath );
                saveFile( pair.getPublic().getEncoded(), publicKeyPath );

                break;
            case "sign":
                privateKeyPath = args[1];
                signaturePath = args[2];
                fileToSignPath = args[3];

                System.out.print( "Enter password (16 letters): " );
                password = in.readLine();

                saveFile( sign( decodePrivateKey( decrypt( password.getBytes(), readFile( privateKeyPath ) ) ), readFile( fileToSignPath ) ), signaturePath );

                break;
            case "ver":
                publicKeyPath = args[1];
                signaturePath = args[2];
                fileToVerifyPath = args[3];

                System.out.println( "signature verifies: " + verify( decodePublicKey( readFile( publicKeyPath ) ), readFile( signaturePath ), readFile( fileToVerifyPath ) ) );

                break;
        }
    }
}
