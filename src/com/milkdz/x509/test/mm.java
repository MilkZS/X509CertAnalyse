package com.milkdz.x509.test;

import com.milkdz.x509.ZX509Certificate;
import com.milkdz.x509.util.StringUtil;

import java.util.Base64;

/**
 * Created by zuoqi@bhz.com.cn on 2019/5/23 11:08
 */
public class mm {

    private static final String cert = "MIIDkDCCAnigAwIBAgIED+kb0DANBgkqhkiG9w0BAQUFADB3MQswCQYDVQQGEwJDTjELMAkGA1UECBMCQkoxEDAOBgNVBAcTB0JFSUpJTkcxFTATBgNVBAoTDEJFSUpJTkcgSERaQjEjMCEGA1UECxMaQkVJSklORyBIRFpCIFJvb3QgRm9yIElDQkMxDTALBgNVBAMTBEhEWkIwHhcNMTkwNzAyMDYwNzA1WhcNMjAwNzAxMDYwNzA1WjAvMQ8wDQYDVQQDEwZURVNUMDExDTALBgNVBAsTBFRFU1QxDTALBgNVBAoTBElDQkMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCYNwMoj1LMhwc/MY1Plq3Qpbqe+T9AaWPzS6NLKGiS8KIr1F9aGdqJvAO8XLyDGGjZmLodFc8eUuSoofgPyz7K64tJXq2hOyRRhLW6GFW9y6Muoe0FYyEUxIFUTDRZUO8p7aVUNGxx1Ela1UBnupXbQAKRymu7M5y4OwMC+9CCa/ZMSJjHS0vAAlSxQBmK2KBvl3/QXQeTPyiUuaKez9/dv7+LW5ZnYBkbPzx72x8JVJE0ZJ6xjkg+F4qbeivGVMfUHBhRecjyEYyHIeFsBAnTJpvAiFaSMbxjB8RKY2qUIvWVaLTEkjMJBctJ4JjUZcxWPxT4ktwNi9xhjCAGGGXjAgMBAAGjbDBqMDsGA1UdIwQ0MDKAFFAydjbC7HrTPkoohQ2z0l4ALwrboReGFWh0dHA6Ly93d3cuYmh6LmNvbS5jboIBKjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSm43w3xp69/V8uDoG1hYaT3V1OtDANBgkqhkiG9w0BAQUFAAOCAQEASPMGHwLDQILyu9ZcHI02SidGrX30fBnfjDYOIW5UxI569EXZyHk1dwFSmTSa/c+YNQvgqea3k1mydtH8fXlE/N5jK7XVJPM2FYRIEcqvnjG16YHzZxgmV5uSOhMrXXAExa+P8nESR5UuDUuL2VTldnVGZ5oUxkE1zBdy1VbwugcG8qRS7zwdZVF6xoE38Of63kBml1CXfSfL50Yk6YdejmJSDb1bcCc15kf04iu42f3mYcde+Ai1WM/tmAfeaAI+Ey305XxHz09PFXQ2vmAFWmbkqLbRfwh/t0yQPg3f8RHfvvpcfffdOWJVRAHt98tvQoarboOXwHUtgu4V+70cGA==";

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
