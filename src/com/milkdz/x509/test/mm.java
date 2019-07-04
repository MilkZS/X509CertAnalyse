package com.milkdz.x509.test;

import com.milkdz.x509.ZX509Certificate;
import com.milkdz.x509.util.StringUtil;

import java.util.Base64;

/**
 * Created by zuoqi@bhz.com.cn on 2019/5/23 11:08
 */
public class mm {

    private static final String cert = "";
    public static void main(String[] args) {
        ZX509Certificate certificate = new ZX509Certificate(Base64.getDecoder().decode(cert));
        System.out.println("============= X509证书解析 =============");
        System.out.println("\n============= Issuer ================");
        System.out.println("OrganizationName :" + certificate.issuer.getOrganizationName());
        System.out.println("OrganizationalUnitName :" + certificate.issuer.getOrganizationalUnitName());
        System.out.println("LocalityName :" + certificate.issuer.getLocalityName());
        System.out.println("CountryName :" + certificate.issuer.getCountryName());
        System.out.println("CommonName :" + certificate.issuer.getCommonName());
        System.out.println("Issuer :" + certificate.issuer.getIssuer());
        System.out.println("StateOrProvinceName :" + certificate.issuer.getStateOrProvinceName());
        System.out.println("\n============= Subject ================");
        System.out.println("OrganizationName :" + certificate.subject.getOrganizationName());
        System.out.println("CountryName :" + certificate.subject.getCountryName());
        System.out.println("OrganizationalUnitName :" + certificate.subject.getOrganizationalUnitName());
        System.out.println("CommonName :" + certificate.subject.getCommonName());
        System.out.println("Subject :" + certificate.subject.getSubject());
        System.out.println("\n============= time ================");
        System.out.println(certificate.time.getStartTimeYMD() + " - " + certificate.time.getEndTimeYMD());
        System.out.println(certificate.time.getStartTimeYMDHMS() + " - " + certificate.time.getEndTimeYMDHMS());
        System.out.println("\n============= version ================");
        System.out.println("version : " + certificate.getVersion());
        System.out.println("\n============= algorithm ================");
        System.out.println("Type : " + certificate.algorithmIdentifier.getType());
        System.out.println("Name : " + certificate.algorithmIdentifier.getName());
        System.out.println("SimpleName :" + certificate.algorithmIdentifier.getSimpleName());
        System.out.println("\n============= subjectPublicKey ================");
        System.out.println("SimpleName : " + certificate.subjectPublicKey.algorithmIdentifier.getSimpleName());
        System.out.println("PublicKeyInfo : " + StringUtil.toHex(certificate.subjectPublicKey.getPublicKeyInfo()));

    }

}
