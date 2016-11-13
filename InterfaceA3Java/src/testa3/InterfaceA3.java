/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package testa3;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.xml.stream.XMLStreamException;
import org.apache.commons.codec.binary.Base64;
import org.json.JSONObject;
import testa3.OnCert.TAssinaXML;

/**
 *
 * @author Edi
 */
public class InterfaceA3 {

    /**
     * @param args the command line arguments
     * @throws java.lang.Exception
     */
    public static void main(String[] args) throws Exception {
        
        char[] header = new char[4];
        char[] body;
        String message;
        
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
            in.read(header, 0, 4);
            int size = getInt(header);
            body = new char[size];
            in.read(body, 0, size);
            
            message = String.valueOf(body);
            
            JOptionPane.showMessageDialog(null, message);
            
        } catch (IOException ioe) {
       
        }
        
        OnCert onCert = new OnCert();
        String certAlias = null;
        
        try {

            String[] certs = OnCert.funcListaCertificados(true);

            JFrame frame = new JFrame("Input Dialog Example 3");
            certAlias = (String) JOptionPane.showInputDialog(frame,
                    "Selecione o certificado para transmitir:",
                    "Certificado Digital",
                    JOptionPane.QUESTION_MESSAGE,
                    null,
                    certs,
                    certs[0]);

        } catch (NoSuchProviderException | IOException | NoSuchAlgorithmException | CertificateException ex) {
            Logger.getLogger(InterfaceA3.class.getName()).log(Level.SEVERE, null, ex);
        }

        TAssinaXML tAssina = new OnCert.TAssinaXML();
        tAssina.strSenhaCertificado = "";
        tAssina.strAliasTokenCert = certAlias;
        tAssina.strArquivoXML = "nfe-unsigned.xml";
        tAssina.strArquivoSaveXML = "nfe-signed.xml";
        
        try {
            
            // Assina o xml
            OnCert.funcAssinaXML(tAssina, "1");
            
            // Envia lote
            String retornoXml = SendLote.sendLot("nfe-signed.xml", tAssina.strAliasTokenCert, tAssina.strSenhaCertificado);
            
            JSONObject retornoJSON = new JSONObject();
            
            byte[] encodedBytes = Base64.encodeBase64(retornoXml.getBytes());
            
            retornoJSON.put("retornoXML", new String(encodedBytes));
            //char[] result = join(new char[] {0x0f, 0x00, 0x00, 0x00}, "{\"ping\":\"pong\"}".toCharArray());
            
            
            char[] result = join(getBytes(retornoJSON.toString().length()), retornoJSON.toString().toCharArray());

            System.out.print(result);

            System.exit(0);
            
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException | XMLStreamException ex) {
            Logger.getLogger(InterfaceA3.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        System.exit(0);
        
    }
    
    private static char[] join(char[] a, char[] b) {
        // join two byte arrays
        final char[] ret = new char[a.length + b.length];
        System.arraycopy(a, 0, ret, 0, a.length);
        System.arraycopy(b, 0, ret, a.length, b.length);
        return ret;
    }
    
    // read the message size from Chrome. This part works correctly.
    public static int getInt(char[] bytes) {
        return (bytes[3] << 24) & 0xff000000
                | (bytes[2] << 16) & 0x00ff0000
                | (bytes[1] << 8) & 0x0000ff00
                | (bytes[0] << 0) & 0x000000ff;
    }
    
    // transform the length into the 32-bit message length. 
    // This part works for small numbers, but does not work for length 2269 for example.
    public static char[] getBytes(int length) {
        return String.format("%c%c%c%c",
                (char) (length & 0xFF),
                (char) ((length >> 8) & 0xFF),
                (char) ((length >> 16) & 0xFF),
                (char) ((length >> 24) & 0xFF)).toCharArray();
    }

}
