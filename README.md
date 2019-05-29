# X509CertAnalyse

## [README OF CHINESE](https://github.com/MilkZS/X509CertAnalyse/blob/master/README_CN.md)

&ensp;&ensp;&ensp;&ensp;Because under Android 5, the X509 certificate parsing used by SDK will make mistakes, which seems to be related to Android system, so in a fit of anger, the toolkit has been modified and optimized. This toolkit is completely independent of any third-party package, pure JAVA code parsing, and no system, SDK.

### Demo

```
System.out.println("============= X509证书解析 =============");
ZX509Certificate certificate = new ZX509Certificate(StringUtil.hexToBytes(cert));

System.out.println("\n============= Issuer ================");
System.out.println("OrganizationName :" + certificate.issuer.getOrganizationName());
System.out.println("CountryName :" + certificate.issuer.getCountryName());
System.out.println("CommonName :" + certificate.issuer.getCommonName());
System.out.println("Issuer :" + certificate.issuer.getIssuer());

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
System.out.println("Type : " + certificate.subjectPublicKey.algorithmIdentifier.getType());
System.out.println("Name : " + certificate.subjectPublicKey.algorithmIdentifier.getName());
System.out.println("SimpleName : " + certificate.subjectPublicKey.algorithmIdentifier.getSimpleName());
System.out.println("PublicKeyInfo : " + StringUtil.toHex(certificate.subjectPublicKey.getPublicKeyInfo()));
```
