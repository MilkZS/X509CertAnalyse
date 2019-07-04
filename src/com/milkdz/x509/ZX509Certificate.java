package com.milkdz.x509;

import com.milkdz.x509.bean.*;
import com.milkdz.x509.impl.*;

/**
 * Created by zuoqi@bhz.com.cn on 2019/5/29 15:58
 */
public class ZX509Certificate {

    private int version;
    public Issuer issuer;
    public Subject subject;
    public ValidityTime time;
    public AlgorithmIdentifier algorithmIdentifier;
    public SubjectPublicKey subjectPublicKey;

    public ZX509Certificate(byte[] certArr) {
        ZX509CertificateImpl certificate = new ZX509CertificateImpl();
        certificate.parse(certArr);
        ZTBSCertificate certificateData = certificate.getM_tbsCertificate();

        DistinguishName issueName = certificateData.getIssuer();
        IssuerImpl issuerImpl = new IssuerImpl();
        issuerImpl.parse(issueName.make());
        this.issuer = issuerImpl.getIssuer();

        DistinguishName subjectName = certificateData.getSubject();
        SubjectImpl subjectimpl = new SubjectImpl();
        subjectimpl.parse(subjectName.make());
        this.subject = subjectimpl.getSubject();

        ValidityTimeimpl validityTimeimpl = certificateData.getValidityTime();
        this.time = validityTimeimpl.getValidityTime();
        this.version = certificateData.getVersion();

        AlgorithmIdentifierImpl algIdentifier = certificateData.getAlgorithmIdentifierImpl();
        this.algorithmIdentifier = algIdentifier.getAlgorithmIdentifier();

        SubjectPublicKeyInfoImpl subjectPublicKeyInfoImpl = certificateData.getSubjectPublicKeyInfoImpl();
        this.subjectPublicKey = subjectPublicKeyInfoImpl.getSubjectPublicKey();
    }

    public int getVersion() {
        return version;
    }
}
