package com.milkdz.x509.bean;

import com.milkdz.x509.tlv.ZTLVBase;
import com.milkdz.x509.tlv.ZTLVContain;
import com.milkdz.x509.util.ByteArrayBuffer;

/**
 * Created by MilkZS on 2019/5/22 16:48
 */
public class AlgorithmIdentifier {

    private ByteArrayBuffer m_algoIdentifier;
    private ByteArrayBuffer m_algoParameter;

    public AlgorithmIdentifier() {
        //目前默认为没有算法参数，都设置为空(05 00)
        byte algoParam[] = new byte[2];
        algoParam[0] = 0x05;
        algoParam[1] = 0x00;
        m_algoParameter = new ByteArrayBuffer(2);
        m_algoParameter.append(algoParam, 0, 2);
    }

    public void setAlgorithmOID(ByteArrayBuffer oid) {
        m_algoIdentifier = new ByteArrayBuffer(oid.length());
        m_algoIdentifier.append(oid.buffer(), 0, oid.length());
    }

    public ByteArrayBuffer getAlgorithmOID() {
        return m_algoIdentifier;
    }

    public void setAlgorithmParam(ByteArrayBuffer param) {
        m_algoParameter.clear();
        m_algoParameter.append(param.buffer(), 0, param.length());
    }

    /*
    AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm               OBJECT IDENTIFIER,
        parameters              ANY DEFINED BY algorithm OPTIONAL  }
    -- contains a value of the type
    -- registered for use with the
    -- algorithm object identifier value
    -- Algorithm OIDs and parameter structures
    */
    public boolean parse(ZTLVBase item) {
        if (item.getTag() != ASNTAGBean.TAG_ASN_SEQUENCE_AND_SEQUENCE_OF) return false;

        ZTLVContain algoCon = new ZTLVContain();
        if (!algoCon.parse(item.getValue())) return false;

        //暂时认为只有两个子项，一个是算法标识符，一个是NULL
        if (algoCon.itemCount() != 2) return false;

        //暂时不处理parameters
        ZTLVBase algorithm = algoCon.getItem(0);
        ZTLVBase parameters = algoCon.getItem(1);

        //保存解析出的算法标识符，参数不予处理，也不进行判断
        m_algoIdentifier = algorithm.getValue();

        if (parameters.getTag() == ASNTAGBean.TAG_ASN_NULL) {
            byte algoParam[] = new byte[2];
            algoParam[0] = 0x05;
            algoParam[1] = 0x00;
            m_algoParameter.clear();
            m_algoParameter.append(algoParam, 0, 2);
        } else {
            m_algoParameter.clear();
            m_algoParameter = parameters.getEncodingData();
        }

        return true;
    }

    public ByteArrayBuffer make() {
        if (m_algoIdentifier.isEmpty()) return null;

        ZTLVBase algoIden = new ZTLVBase();
        algoIden.setTag(ASNTAGBean.TAG_ASN_OBJECT_IDENTIFIER);
        algoIden.setValue(m_algoIdentifier);

        ZTLVBase derItem = new ZTLVBase();
        derItem.setTag(ASNTAGBean.TAG_ASN_SEQUENCE_AND_SEQUENCE_OF);
        ByteArrayBuffer temp = new ByteArrayBuffer(algoIden.getEncodingData().length() + m_algoParameter.length());
        temp.append(algoIden.getEncodingData().buffer(), 0, algoIden.getEncodingData().length());
        temp.append(m_algoParameter.buffer(), 0, m_algoParameter.length());
        derItem.setValue(temp);
        return derItem.getEncodingData();
    }

    public boolean setAlgorithm(int sigatureAlgo) {
        ByteArrayBuffer signAlgo = getSignatureOID(sigatureAlgo);
        if (signAlgo == null || signAlgo.isEmpty()) return false;
        setAlgorithmOID(signAlgo);
        return true;
    }

    public static ByteArrayBuffer getSignatureOID(int sigatureAlgo) {
        //1.2.840.113549.1.1.1
        byte bRSA[] = {0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x01};
        //1.2.840.113549.1.1.2
        byte bMD2RSA[] = {0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x02};
        //1.2.840.113549.1.1.3
        byte bMD4RSA[] = {0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x03};
        //1.2.840.113549.1.1.4
        byte bMD5RSA[] = {0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x04};
        //1.2.840.113549.1.1.5
        byte bSHA1RSA[] = {0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x05};
        //1.2.156.10197.1.501
        byte bSm3Sm2[] = {0x2A, (byte) 0x81, 0x1c, (byte) 0xcf, 0x55, 0x01, (byte) 0x83, 0x75};
        //1.2.156.10197.1.301
        byte bSM2Encrypt[] = {0x2A, (byte) 0x81, 0x1c, (byte) 0xcf, 0x55, 0x01, (byte) 0x82, 0x2d};
        //1.2.840.10045.2.1
        byte bECPublicKey[] = {0x2A, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x02, 0x01};
        //1.2.840.113549.1.1.11
        byte bSHA256RSA[] = {0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x0B};
        //1.2.840.113549.1.1.12
        byte bSHA384RSA[] = {0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x0C};
        //1.2.840.113549.1.1.13
        byte bSHA512RSA[] = {0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x0D};

        ByteArrayBuffer temp = new ByteArrayBuffer(9);
        switch (sigatureAlgo) {
            case ASNTAGBean.rsaEncrypt: {
                temp.append(bRSA, 0, bRSA.length);
                return temp;
            }
            case ASNTAGBean.ecPublicKey: {
                temp.append(bECPublicKey, 0, bECPublicKey.length);
                return temp;
            }
            case ASNTAGBean.sha1Rsa: {
                temp.append(bSHA1RSA, 0, bSHA1RSA.length);
                return temp;
            }
            case ASNTAGBean.md2Rsa: {
                temp.append(bMD2RSA, 0, bMD2RSA.length);
                return temp;
            }
            case ASNTAGBean.md4Rsa: {
                temp.append(bMD4RSA, 0, bMD4RSA.length);
                return temp;
            }
            case ASNTAGBean.md5Rsa: {
                temp.append(bMD5RSA, 0, bMD5RSA.length);
                return temp;
            }
            case ASNTAGBean.sm3sm2: {
                temp.append(bSm3Sm2, 0, bSm3Sm2.length);
                return temp;
            }
            case ASNTAGBean.ecEncrypt: {
                temp.append(bSM2Encrypt, 0, bSM2Encrypt.length);
                return temp;
            }
            case ASNTAGBean.sha256Rsa: {
                temp.append(bSHA256RSA, 0, bSHA256RSA.length);
                return temp;
            }
            case ASNTAGBean.sha384Rsa: {
                temp.append(bSHA384RSA, 0, bSHA384RSA.length);
                return temp;
            }
            case ASNTAGBean.sha512Rsa: {
                temp.append(bSHA512RSA, 0, bSHA512RSA.length);
                return temp;
            }
            default:
                return null;
        }
    }
}
