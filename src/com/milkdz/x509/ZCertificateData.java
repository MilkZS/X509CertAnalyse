package com.milkdz.x509;

import com.milkdz.x509.bean.*;
import com.milkdz.x509.tlv.ZTLVBase;
import com.milkdz.x509.tlv.ZTLVContain;
import com.milkdz.x509.tlv.ZTLVInteger;
import com.milkdz.x509.util.ByteArrayBuffer;

/**
 * Created by MilkZS on 2019/5/22 16:38
 */
public class ZCertificateData {

    /*
	TBSCertificate ::= SEQUENCE {
	    version [0] EXPLICIT Version DEFAULT v1, --证书版本号
	    serialNumber CertificateSerialNumber, --证书序列号，对同一CA所颁发的证书，序列号唯一标识证书
	    signature AlgorithmIdentifier, --证书签名算法标识
	    issuer Name, --证书发行者名称
	    validityTime ValidityTime, --证书有效期
	    subject Name, --证书主体名称
	    subjectPublicKeyInfo SubjectPublicKeyInfo, --证书公钥
	    issuerUniqueID [1] IMPLICIT UniqueIdentifier OPTIONAL, -- 证书发行者ID(可选)，只在证书版本2、3中才有
	    subjectUniqueID [2] IMPLICIT UniqueIdentifier OPTIONAL, --证书主体ID(可选)，只在证书版本2、3中才有
	    extensions [3] EXPLICIT Extensions OPTIONAL --证书扩展段（可选），只在证书版本2、3中才有 }
	*/
    private int version;
    private ZTLVInteger serialNumber;
    private AlgorithmIdentifier algorithmIdentifier;
    private DistinguishName issuer;
    private ValidityTime validityTime;
    private DistinguishName subject;
    private SubjectPublicKeyInfo subjectPublicKeyInfo;

    public ZCertificateData() {
        this.serialNumber = new ZTLVInteger();
        this.algorithmIdentifier = new AlgorithmIdentifier();
        this.issuer = new DistinguishName();
        this.validityTime = new ValidityTime();
        this.subject = new DistinguishName();
        this.subjectPublicKeyInfo = new SubjectPublicKeyInfo();
    }

    public boolean parse(ZTLVBase cerBody) {
        ByteArrayBuffer certData = cerBody.getValue();
        if (certData == null) return false;

        ZTLVContain containBody = new ZTLVContain();
        if (!containBody.parse(certData)) return false;

        // TODO 目前先只解析前7项,之后扩展可以从这个判断入手
        if (containBody.itemCount() < 7) return false;

        // SEQUENCE 为有序集合，故可以按顺序读取
        ZTLVBase versionBase = containBody.getItem(0);
        ZTLVBase serialBase = containBody.getItem(1);
        ZTLVBase algorithmIdentifierBase = containBody.getItem(2);
        ZTLVBase issuerBase = containBody.getItem(3);
        ZTLVBase validateBase = containBody.getItem(4);
        ZTLVBase subjectBase = containBody.getItem(5);
        ZTLVBase publicKeyInfoBase = containBody.getItem(6);

        // 版本号
        if (!parseVersion(versionBase)) return false;
        if (!serialNumber.parse(serialBase)) return false;
        if (!algorithmIdentifier.parse(algorithmIdentifierBase)) return false;
        if (!issuer.parse(issuerBase)) return false;
        if (!validityTime.parse(validateBase)) return false;
        if (!subject.parse(subjectBase)) return false;
        return subjectPublicKeyInfo.parse(publicKeyInfoBase);
    }

    private boolean parseVersion(ZTLVBase base) {
        //此时得到的TLV串应该是[A0 03 02 01 n]
        //注:由于TAG值只比对bit1-bit5，因此A0此处应为00
        if (base.getTag() != 0x00 || base.getLength() != 3) return false;

        byte[] versionByteArr = base.getValue().buffer();
        if (versionByteArr[0] != ASNTAGBean.TAG_ASN_INTEGER || versionByteArr[1] != ASNTAGBean.TAG_ASN_BOOLEAN)
            return false;

        //Version,目前没有做值校验，但实际上最高版本号目前应该只有V3
        this.version = versionByteArr[2] + 1;
        return true;
    }

    public int getVersion() {
        return version;
    }

    public ZTLVInteger getSerialNumber() {
        return serialNumber;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    public DistinguishName getIssuer() {
        return issuer;
    }

    public ValidityTime getValidityTime() {
        return validityTime;
    }

    public DistinguishName getSubject() {
        return subject;
    }

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
        return subjectPublicKeyInfo;
    }
}
