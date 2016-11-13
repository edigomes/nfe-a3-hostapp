package testa3;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

import java.security.KeyStore;  
import java.security.cert.X509Certificate;  
import java.text.SimpleDateFormat;  
import java.util.Enumeration;  
  
/** 
* Acessa dados dos Certificados Digitais por meio do repositorio do Windows (SunMSCAPI). 
*  
* @author Copyright (c) 2012 Maciel Gonçalves 
*  
* Este programa é software livre, você pode redistribuí-lo e ou modificá-lo 
* sob os termos da Licença Pública Geral GNU como publicada pela Free 
* Software Foundation, tanto a versão 2 da Licença, ou (a seu critério) 
* qualquer versão posterior. 
*  
* http://www.gnu.org/licenses/gpl.txt 
*  
*/  
public class DadosCertificadoRepositorioWindows {  
    private static final SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");  
      
    public static void main(String[] args) {  
        try {  
            KeyStore keyStore = KeyStore.getInstance("Windows-MY", "SunMSCAPI");  
            keyStore.load(null, null);  
              
            Enumeration <String> al = keyStore.aliases();  
            while (al.hasMoreElements()) {  
                String alias = al.nextElement();  
                info("--------------------------------------------------------");  
                if (keyStore.containsAlias(alias)) {  
                    info("Emitido para........: " + alias);  
  
                    X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);  
                    info("SubjectDN...........: " + cert.getSubjectDN().toString());  
                    info("Version.............: " + cert.getVersion());  
                    info("SerialNumber........: " + cert.getSerialNumber());  
                    info("SigAlgName..........: " + cert.getSigAlgName());  
                    info("Válido a partir de..: " + dateFormat.format(cert.getNotBefore()));  
                    info("Válido até..........: " + dateFormat.format(cert.getNotAfter()));    
                } else {  
                    info("Alias doesn't exists : " + alias);  
                }  
            }  
        } catch (Exception e) {  
            error(e.toString());  
        }  
    }  
  
    /** 
     * Info. 
     * @param log 
     */  
    private static void info(String log) {  
        System.out.println("INFO: " + log);  
    }  
  
    /** 
     * Error. 
     * @param log 
     */  
    private static void error(String log) {  
        System.out.println("ERROR: " + log);  
    }  
  
}  