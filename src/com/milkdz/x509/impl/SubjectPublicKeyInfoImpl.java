package com.milkdz.x509.impl;

import com.milkdz.x509.bean.ASNTAGBean;
import com.milkdz.x509.bean.SubjectPublicKey;
import com.milkdz.x509.impl.AlgorithmIdentifierImpl;
import com.milkdz.x509.tlv.ZTLVBase;
import com.milkdz.x509.tlv.ZTLVBitString;
import com.milkdz.x509.tlv.ZTLVContain;
import com.milkdz.x509.tlv.ZTLVInteger;
import com.milkdz.x509.util.ByteArrayBuffer;

/**
 * Created by MilkZS on 2019/5/22 16:51
 */
public class SubjectPublicKeyInfoImpl {

    private SubjectPublicKey subjectPublicKey;
    private AlgorithmIdentifierImpl algorithmIdentifierImpl;
    private ZTLVBitString publicKeyBitStr;

    public SubjectPublicKeyInfoImpl() {
        this.subjectPublicKey = new SubjectPublicKey();
        this.algorithmIdentifierImpl = new AlgorithmIdentifierImpl();
        publicKeyBitStr = new ZTLVBitString();
    }

    public void setAlgorithmIdentifier(AlgorithmIdentifierImpl algoIdentifier) {
        algorithmIdentifierImpl = algoIdentifier;
    }

    public AlgorithmIdentifierImpl getAlgorithmIdentifier() {
        return algorithmIdentifierImpl;
    }

    //将传入的纯公钥
    //RSAPublicKey ::= SEQUENCE {
//	         modulus            INTEGER, -- n
//	         publicExponent     INTEGER  -- e -- }
    //SM2PublicKey ::= SEQUENCE {
    //		 04+X+Y			}
    //
    public boolean setPublicKey(boolean isRSA, byte[] publicKey) {
        if (!isRSA) {
            if (publicKey.length == 64 || (publicKey.length == 65 && publicKey[0] == 0x04)) {
                byte[] pubkey = new byte[65];
                if (publicKey.length == 64) {
                    pubkey[0] = 0x04;
                    System.arraycopy(publicKey, 0, pubkey, 1, 64);
                } else {
                    System.arraycopy(publicKey, 0, pubkey, 0, 65);
                }
                publicKeyBitStr.setValue(pubkey);
                return true;
            } else {
                return false;
            }
        } else {
            ZTLVInteger module = new ZTLVInteger();
            ByteArrayBuffer pubKey = null;
            if (publicKey[0] != 0) {
                pubKey = new ByteArrayBuffer(publicKey.length + 1);
                byte temp[] = new byte[1];
                pubKey.append(temp, 0, 1);
                pubKey.append(publicKey, 0, publicKey.length);
            } else {
                pubKey = new ByteArrayBuffer(publicKey.length);
                pubKey.append(publicKey, 0, publicKey.length);
            }
            module.setValue(pubKey);
            ZTLVInteger exponent = new ZTLVInteger();
            byte[] e = {01, 00, 01};
            ByteArrayBuffer tempe = new ByteArrayBuffer(3);
            tempe.append(e, 0, 3);
            exponent.setValue(tempe);

            ZTLVBase item = new ZTLVBase();
            item.setTag(ASNTAGBean.TAG_ASN_SEQUENCE_AND_SEQUENCE_OF);

            ByteArrayBuffer tempItem = new ByteArrayBuffer(module.make().length() + exponent.make().length());
            tempItem.append(module.make().buffer(), 0, module.make().length());
            tempItem.append(exponent.make().buffer(), 0, exponent.make().length());
            item.setValue(tempItem);

            publicKeyBitStr.setValue(item.getEncodingData());
            return true;
        }
    }

    public void setPublicKey(ZTLVBitString publicKey) {
        publicKeyBitStr = publicKey;
    }

    public ZTLVBitString getPublicKey() {
        return publicKeyBitStr;
    }

    public boolean parse(ZTLVBase item) {
        if (item.getTag() != ASNTAGBean.TAG_ASN_SEQUENCE_AND_SEQUENCE_OF) return false;

        ZTLVContain container = new ZTLVContain();
        if (!container.parse(item.getValue())) return false;
        if (container.itemCount() != 2) return false;

        ZTLVBase algoIdentifier = container.getItem(0);
        ZTLVBase publicKey = container.getItem(1);

        // 算法标识
        if (!algorithmIdentifierImpl.parse(algoIdentifier)) return false;
        // 公钥
        return publicKeyBitStr.parse(publicKey);
    }

    public ByteArrayBuffer make() {
        ByteArrayBuffer algoIdentifiterDer = algorithmIdentifierImpl.make();
        ByteArrayBuffer publicKeyDer = publicKeyBitStr.make();

        if (algoIdentifiterDer.isEmpty() || publicKeyDer.isEmpty()) {
            return null;
        }

        ZTLVBase outDer = new ZTLVBase();
        outDer.setTag(ASNTAGBean.TAG_ASN_SEQUENCE_AND_SEQUENCE_OF);

        ByteArrayBuffer tempoutDer = new ByteArrayBuffer(algoIdentifiterDer.length() + publicKeyDer.length());
        tempoutDer.append(algoIdentifiterDer.buffer(), 0, algoIdentifiterDer.length());
        tempoutDer.append(publicKeyDer.buffer(), 0, publicKeyDer.length());
        outDer.setValue(tempoutDer);
        return outDer.getEncodingData();
    }

    public SubjectPublicKey getSubjectPublicKey() {
        this.subjectPublicKey.algorithmIdentifier = algorithmIdentifierImpl.getAlgorithmIdentifier();
        this.subjectPublicKey.setPublicKeyInfo(publicKeyBitStr.getValue().buffer());
        return this.subjectPublicKey;
    }
}
