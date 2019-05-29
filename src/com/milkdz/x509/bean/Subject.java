package com.milkdz.x509.bean;

/**
 * Created by MilkZS on 2019/5/22 16:51
 */
public class Subject {

    private String countryName;
    private String organizationName;
    private String organizationalUnitName;
    private String commonName;
    private String subject;

    public void setCountryName(String countryName) {
        this.countryName = countryName;
    }

    public void setOrganizationName(String organizationName) {
        this.organizationName = organizationName;
    }

    public void setOrganizationalUnitName(String organizationalUnitName) {
        this.organizationalUnitName = organizationalUnitName;
    }

    public void setCommonName(String commonName) {
        this.commonName = commonName;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getSubject() {
        return subject;
    }

    public String getCountryName() {
        return countryName;
    }

    public String getOrganizationName() {
        return organizationName;
    }

    public String getOrganizationalUnitName() {
        return organizationalUnitName;
    }

    public String getCommonName() {
        return commonName;
    }
}
