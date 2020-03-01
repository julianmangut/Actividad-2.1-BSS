/**
     * RC4 cipher.
     *
     * Adapted from BouncyCastle.org
     * LMMB, Febrero 2017
     * 
*/

import java.io.*;
import java.util.Scanner;

public class RC4
{
    private final static int STATE_LENGTH = 256;    // Tamaño de la matriz

    /*
     * variables to hold the state of the RC4 engine
     * during encryption and decryption
     */

    private byte[]      engineState = null;
    private int         x = 0;
    private int         y = 0;
    private byte[]      workingKey = null;

    /**
     * initialize a RC4 cipher. 
     * @param key key for the cipher.
     */
    public void init(byte[] key){
            workingKey = key;
            setKey(workingKey);
    }


    public String getAlgorithmName()
    {
        return "RC4";
    }

    public byte returnByte(byte in)
    {
        x = (x + 1) & 0xff;
        y = (engineState[x] + y) & 0xff;

        // SWAP
        byte tmp = engineState[x];
        engineState[x] = engineState[y];
        engineState[y] = tmp;

        // XOR
        return (byte)(in ^ engineState[(engineState[x] + engineState[y]) & 0xff]);
    }

    public void processBytes(   // PRGA y XOR
        byte[]     in, 
        int     inOff, 
        int     len, 
        byte[]     out, 
        int     outOff)
    {
        // if ((inOff + len) > in.length)
        // {
        //     System.out.println("Input buffer too short");
        // }

        // if ((outOff + len) > out.length)
        // {
        // 	System.out.println("Output buffer too short");
        // }

        int i = 0; 
        int lenKeyStream = 0;

        int lengthTextoClaro = 0;
           
        do {
            lenKeyStream = lenKeyStream + len;

            while (i < lenKeyStream && i < in.length) {
                x = (x + 1) & 0xff;     // & 0xff realiza el mismo efecto que mod 256
                y = (engineState[x] + y) & 0xff;

                // SWAP
                byte tmp = engineState[x];
                engineState[x] = engineState[y];
                engineState[y] = tmp;

                // XOR
                out[i+outOff] = (byte)(in[i + inOff]        // XOR con el texto en claro (in) para la obtener el criptograma
                    ^ engineState[(engineState[x] + engineState[y]) & 0xff]);

                lengthTextoClaro++;
                
                i++;
            }
        } while (lengthTextoClaro > lenKeyStream);
        
    }

    public void reset()
    {
        setKey(workingKey);
    }

    // Private implementation

    private void setKey(byte[] keyBytes)    // Realización del KSA
    {
        workingKey = keyBytes;

        // System.out.println("The key length is ; "+ workingKey.length);

        x = 0;
        y = 0;

        if (engineState == null)
        {
            engineState = new byte[STATE_LENGTH];
        }

        // Reset the state of the engine
        for (int i=0; i < STATE_LENGTH; i++)    // Inicialización del vector S con los valores de 0 a 255 para el desarrollo del KSA
        {
            engineState[i] = (byte)i;
        }
        
        int i1 = 0;
        int i2 = 0;

        for (int i=0; i < STATE_LENGTH; i++)    // Desarrollo del KSA (Key Scheduling Algorithm)
        {
            i2 = ((keyBytes[i1] & 0xff) + engineState[i] + i2) & 0xff;
            // Do the byte-swap inline
            byte tmp = engineState[i];  // Guarda el valor que esta en la posición i para poder intercambiarlo con el que se encuentra en la posición i2 (Calculada previamente)
            engineState[i] = engineState[i2];
            engineState[i2] = tmp;
            i1 = (i1+1) % keyBytes.length; 
        }
    }


  public static void main(String args[]) throws Exception {
	
      String keyword = "Key";
      String texto= "Plaintext";
      int tamañoUsuario = 0;
            
	  System.out.println("\nBiometria y Seguridad de Sistemas");
	  System.out.println("Ejemplo de RC4 v0.1 febrero 2017, LMMB\n");
	  System.out.print("Introduce la clave (hasta 256 caracteres):");
	  BufferedReader br = new BufferedReader(new InputStreamReader(System.in));     // Solicitud de la clave
      keyword = br.readLine();

	  System.out.print("\nIntroduce el texto a cifrar:");
      texto = br.readLine();    // Lectura del texto introducido
      
      System.out.println("Tamaño del KeyStream: ");
      tamañoUsuario = br.read();
	  
      byte[] keytest = keyword.getBytes(); // Convertir clave en bytes

      
      byte[] text = texto.getBytes();   // Convertir texto en bytes
      
      byte[] cipher = new byte[text.length];
      byte[] backtext = new byte[text.length];
            
      System.out.print("\n Plain text:    ");
      for (int i = 0; i < text.length; i++) {          
          System.out.printf("0x%02X",text[i]);  // Se muestra el texto plano en formato hexadecimal        
      }    

      System.out.print("\n");

      // ENCRIPTACION
      RC4 rc4 = new RC4();
      rc4.init(keytest);
      rc4.processBytes(text,0,tamañoUsuario,cipher,0);

      System.out.print("\n Cipher text:   ");
      for (int i = 0; i < cipher.length; i++) {          
          System.out.printf("0x%02X",cipher[i]);    // Se muestra el texto cifrado en formato hexadecimal       
      }    

      System.out.print("\n");
      
      // DESENCRIPTACION
      rc4 = new RC4();
      rc4.init(keytest);
      rc4.processBytes(cipher,0,cipher.length,backtext,0);
      
      System.out.print("\n Decipher text: ");
      for (int i = 0; i < backtext.length; i++) {          
          System.out.printf("0x%02X",backtext[i]);  // Se muestra el texto descifrado en formato hexadecimal          
      } 
      System.out.println();
  }  
}

