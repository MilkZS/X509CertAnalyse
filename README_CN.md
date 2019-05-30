# X509CertAnalyse

## [README OF ENGLISH](https://github.com/MilkZS/X509CertAnalyse/blob/master/README.md)

&ensp;&ensp;&ensp;&ensp;由于Android 5以下，SDK自带的X509证书解析使用会出错，貌似和Android系统有关，所以一怒之下， 修改优化了这个工具包，这个工具包完全不依赖任何第三方包，纯JAVA代码解析，不依赖任何系统，SDK。

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
