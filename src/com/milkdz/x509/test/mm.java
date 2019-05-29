package com.milkdz.x509.test;

import com.milkdz.x509.ZCertificateData;
import com.milkdz.x509.ZX509Certificate;
import com.milkdz.x509.bean.DistinguishName;
import com.milkdz.x509.bean.Issuer;
import com.milkdz.x509.bean.Subject;
import com.milkdz.x509.util.ByteArrayBuffer;
import com.milkdz.x509.util.StringUtil;

/**
 * Created by zuoqi@bhz.com.cn on 2019/5/23 11:08
 */
public class mm {

    private static final String cert = "308202983082023ba003020102020600a56f5fb5c7300c06082a811ccf5501837505003063310b300906035504061302434e31293027060355040a0c2049434243534d32000000000000000000000000000000000000000000000000003129302706035504030c2049434243534d3243414348494c44000000000000000000000000000000000000301e170d3139303532323135343933335a170d3230303532313135343933335a30818e310b300906035504061302434e31293027060355040a0c20430000000000000000000000000000000000000000000000000000000000000031293027060355040b0c204368696e650000000000000000000000000000000000000000000000000000003129302706035504030c20534d3235360000000000000000000000000000000000000000000000000000003059301306072a8648ce3d020106082a811ccf5501822d03420004ed3ccd2d0bd1f6a4cfa3aadcb10ef34fdab61d01ed367042f38f8d64365c373c94b002f10a03577de9f1e1aa261dd22b22600eb1995e2354b99c83c97d717228a381ac3081a9301f0603551d23041830168014872e0a1ce624719dc394fcdb3bc0ed67f27166c030090603551d1304023000304f0603551d1f044830463044a042a040a43e303c310d300b06035504030c0463726c33310c300a060355040b0c0363726c3110300e060355040a0c0749434243534d32310b300906035504061302434e300b0603551d0f040403020780301d0603551d0e04160414d51256804ee3e35c3724246b7e4c5abd0f8a4144300c06082a811ccf55018375050003490030460221005df22a59a5b9ef1fc188a146cb4155a8639b6711e5ab47e7fb061fbede9969c1022100df4d4144eace5966a9c3013eff5c6e8602ff0104cb4a8f550bd481ffc863e19e";

    public static void main(String[] args) {
        byte[] certArr = StringUtil.hexToBytes(cert);
        ZX509Certificate certificate = new ZX509Certificate();
        certificate.parse(certArr);
        ZCertificateData certificateData = certificate.getM_tbsCertificate();
        DistinguishName issueName = certificateData.getIssuer();
        Issuer issuer = new Issuer();
        ByteArrayBuffer byteArrayBuffer = issueName.make();
//        System.out.println(StringUtil.toHex(byteArrayBuffer.buffer()));
        issuer.parse(byteArrayBuffer);
//        System.out.println(issuer.getIssuer() + "/" + issuer.getCommonName() + "/" + issuer.getCountryName() + "/" + issuer.getOrganizationName());

        DistinguishName subjectName = certificateData.getSubject();
        Subject subject = new Subject();
        ByteArrayBuffer buffer = subjectName.make();
        System.out.println(StringUtil.toHex(buffer.buffer()));
        subject.parse(buffer);
        System.out.println(subject.getSubject() + "/" + subject.getCommonName() + "/"
                + subject.getCountryName() + "/"+subject.getOrganizationName() + "/" + subject.getOrganizationnlUnitName());
    }

}
