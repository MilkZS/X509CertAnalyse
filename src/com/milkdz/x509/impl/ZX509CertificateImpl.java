package com.milkdz.x509.impl;

import com.milkdz.x509.tlv.ZTLVBase;
import com.milkdz.x509.tlv.ZTLVBitString;
import com.milkdz.x509.tlv.ZTLVContain;
import com.milkdz.x509.util.ByteArrayBuffer;

/**
 * Created by MilkZS on 2019/5/22 11:03
 */
public class ZX509CertificateImpl {

    private ByteArrayBuffer m_certData;
    private int m_certLength;


    private ZCertificateData m_tbsCertificate = new ZCertificateData();               //证书主体
    private AlgorithmIdentifierImpl m_signatureAlgorithm = new AlgorithmIdentifierImpl();    //签名算法标识（签名算法OID，应与TBS中的签名算法标识一致）
    private ZTLVBitString m_signatureValue = new ZTLVBitString();              //签名值

    /*
    Certificate  ::=  SEQUENCE  {
        tbsCertificate       TBSCertificate，
        signatureAlgorithm   AlgorithmIdentifierImpl，
        signatureValue       BIT STRING  }
    */
    public boolean parse(byte[] pbData) {
        m_certData = new ByteArrayBuffer(pbData.length);
        m_certData.append(pbData, 0, pbData.length);

        //解析整张证书
        ZTLVBase cert = new ZTLVBase();
        if (!ZTLVBase.dump(m_certData, cert)) return false;

        //获取证书body
        ByteArrayBuffer certBody = cert.getValue();
        if (certBody == null) return false;

        //解析证书body,证书body应该由3个SEQUENCE结构组成:TBSCertificate,SignatureAlgorithm(摘要算法)和SignatureValue(对TBS部分的签名值的摘要)
        ZTLVContain certCon = new ZTLVContain();
        if (!certCon.parse(certBody)) return false;
        if (3 != certCon.itemCount()) return false;


        ZTLVBase tbsCert = certCon.getItem(0);
        ZTLVBase signAlgo = certCon.getItem(1);
        ZTLVBase signature = certCon.getItem(2);

        //解析证书主体部分
        if (!m_tbsCertificate.parse(tbsCert)) return false;

        //解析签名算法部分
        if (!m_signatureAlgorithm.parse(signAlgo)) return false;

        //解析签名值
        if (!m_signatureValue.parse(signature)) return false;

        m_certLength = cert.getEncodingDataSize();
        return true;
    }

    public ByteArrayBuffer getM_certData() {
        return m_certData;
    }

    public int getM_certLength() {
        return m_certLength;
    }

    public ZCertificateData getM_tbsCertificate() {
        return m_tbsCertificate;
    }

    public AlgorithmIdentifierImpl getM_signatureAlgorithm() {
        return m_signatureAlgorithm;
    }

    public ZTLVBitString getM_signatureValue() {
        return m_signatureValue;
    }
}
