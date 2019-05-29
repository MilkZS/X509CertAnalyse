package com.milkdz.x509.bean;

/**
 * Created by zuoqi@bhz.com.cn on 2019/5/29 17:04
 */
public class SubjectPublicKey {

    public AlgorithmIdentifier algorithmIdentifier;
    private byte[] publicKeyInfo;

    public void setPublicKeyInfo(byte[] publicKeyInfo) {
        this.publicKeyInfo = publicKeyInfo;
    }

    public byte[] getPublicKeyInfo() {
        return publicKeyInfo;
    }
}
