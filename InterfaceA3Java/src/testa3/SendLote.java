/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package testa3;

import br.inf.portalfiscal.www.nfe.wsdl.autoriazacao.NfeAutorizacaoStub;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.commons.httpclient.protocol.Protocol;

/**
 *
 * @author Edi
 */
public class SendLote {

    private static final int SSL_PORT = 443;

    public static String sendLot(String caminhoArquivo, String certAlias, String certPass) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, XMLStreamException, JAXBException {

        KeyStore ks = KeyStore.getInstance("Windows-MY");
        ks.load(null, null);

        String codigoDoEstado = "26";

        /**
         * Enderecos de Homoloção do Sefaz Virtual RS para cada WebService
         * existe um endereco Diferente.
         */
        /**
         *
         * homologaçao
         */
        URL NFeAutorizacao = new URL("https://nfehomolog.sefaz.pe.gov.br/nfe-service/services/NfeAutorizacao");
        //URL NFeRetAutorizacao  = new URL("https://nfehomolog.sefaz.pe.gov.br/nfe-service/services/NfeRetAutorizacao");
        //URL NfeInutilizacao  = new URL("https://nfce-homologacao.svrs.rs.gov.br/ws/nfeinutilizacao/nfeinutilizacao2.asmx");  
        //URL NfeConsultaProtocolo  = new URL("https://nfce-homologacao.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta2.asmx");  
        //URL NfeStatusServico  = new URL("https://nfehomolog.sefaz.pe.gov.br/nfe-service/services/NfeStatusServico2");  
        //URL RecepcaoEvento  = new URL("https://nfce-homologacao.svrs.rs.gov.br/ws/recepcaoevento/recepcaoevento.asmx");  

        X509Certificate certificate = (X509Certificate) ks.getCertificate(certAlias);
        PrivateKey privateKey = (PrivateKey) ks.getKey(certAlias, certPass.toCharArray());
        SocketFactoryDinamico socketFactoryDinamico = new SocketFactoryDinamico(certificate, privateKey);
        socketFactoryDinamico.setFileCacerts("NFeCacerts");

        Protocol protocol = new Protocol("https", socketFactoryDinamico, SSL_PORT);
        Protocol.registerProtocol("https", protocol);

        /**
         * Envia NF-e *
         */
        String xml = lerXML(caminhoArquivo);

        StringBuilder xmlEnv = new StringBuilder();

        xmlEnv.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?><enviNFe xmlns=\"http://www.portalfiscal.inf.br/nfe\" versao=\"3.10\">").
                append("<idLote>12312322322</idLote>").
                append("<indSinc>1</indSinc>").
                append(xml.replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "")).
                append("</enviNFe>");

        OMElement ome = AXIOMUtil.stringToOM(xmlEnv.toString());

        NfeAutorizacaoStub.NfeDadosMsg dadosMsg = new NfeAutorizacaoStub.NfeDadosMsg();
        dadosMsg.setExtraElement(ome);
        NfeAutorizacaoStub.NfeCabecMsg nfeCabecMsg = new NfeAutorizacaoStub.NfeCabecMsg();
        nfeCabecMsg.setCUF(codigoDoEstado);
        nfeCabecMsg.setVersaoDados("3.10");
        NfeAutorizacaoStub.NfeCabecMsgE nfeCabecMsgE = new NfeAutorizacaoStub.NfeCabecMsgE();
        nfeCabecMsgE.setNfeCabecMsg(nfeCabecMsg);
        NfeAutorizacaoStub stub = new NfeAutorizacaoStub(NFeAutorizacao.toString());
        NfeAutorizacaoStub.NfeAutorizacaoLoteResult result = stub.nfeAutorizacaoLote(dadosMsg, nfeCabecMsgE);

        String retorno = result.getExtraElement().toString();

        //System.out.println(retorno);

        return retorno;

    }

    public static String lerXML(String caminhoArquivo) {
        try {
            String linha = null;
            StringBuilder xml = new StringBuilder();

            BufferedReader in = new BufferedReader(new InputStreamReader(
                    new FileInputStream(caminhoArquivo), "UTF-8"));
            while ((linha = in.readLine()) != null) {
                xml.append(linha);
            }
            in.close();

            return xml.toString();
        } catch (IOException e) {
            //salvaLog.registraErro("ManagerString", "lerXML", e);  
            return null;
        }
    }
}
