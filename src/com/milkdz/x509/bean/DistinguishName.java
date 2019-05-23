package com.milkdz.x509.bean;

import com.milkdz.x509.tlv.ZTLVBase;
import com.milkdz.x509.util.ByteArrayBuffer;

/**
 * Created by MilkZS on 2019/5/23 10:51
 */
public class DistinguishName {

    private ZTLVBase m_dn = new ZTLVBase();
    private boolean m_bDnIsModified;

    public DistinguishName() {
        m_bDnIsModified = false;
    }

    public ByteArrayBuffer make() {
        if (!m_bDnIsModified) return m_dn.getEncodingData();
        return m_dn.getEncodingData();
    }

    public boolean parse(ZTLVBase derDN) {
        if (derDN.getTag() != ASNTAGBean.TAG_ASN_SEQUENCE_AND_SEQUENCE_OF) return false;
        m_dn = derDN;
        m_bDnIsModified = false;
        return true;
    }
}
