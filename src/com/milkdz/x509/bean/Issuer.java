package com.milkdz.x509.bean;

/**
 * Created by MilkZS on 2019/5/22 16:49
 */
public class Issuer {

    private String countryName;
    private String stateOrProvinceName;
    private String localityName;
    private String organizationName;
    private String organizationalUnitName;
    private String commonName;
    private String issuer;

    public void setCountryName(String countryName) {
        this.countryName = countryName;
    }

    public void setOrganizationName(String organizationName) {
        this.organizationName = organizationName;
    }

    public void setCommonName(String commonName) {
        this.commonName = commonName;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public void setStateOrProvinceName(String stateOrProvinceName) {
        this.stateOrProvinceName = stateOrProvinceName;
    }

    public void setLocalityName(String localityName) {
        this.localityName = localityName;
    }

    public void setOrganizationalUnitName(String organizationalUnitName) {
        this.organizationalUnitName = organizationalUnitName;
    }

    public String getStateOrProvinceName() {
        return stateOrProvinceName;
    }

    public String getLocalityName() {
        return localityName;
    }

    public String getOrganizationalUnitName() {
        return organizationalUnitName;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getCountryName() {
        return countryName;
    }

    public String getOrganizationName() {
        return organizationName;
    }

    public String getCommonName() {
        return commonName;
    }
}
