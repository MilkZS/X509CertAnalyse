package com.milkdz.x509.bean;

import com.milkdz.x509.tlv.ZTLVBase;
import com.milkdz.x509.tlv.ZTLVContain;
import com.milkdz.x509.util.ByteArrayBuffer;

/**
 * Created by MilkZS on 2019/5/22 16:49
 */
public class Issuer {

    private String countryName;
    private String organizationName;
    private String commonName;
    private String issuer;

    public boolean parse(ByteArrayBuffer issueData) {
        try {
            ZTLVBase head = new ZTLVBase();
            head.parse(issueData);
            // 获取SEQUENCE
            ZTLVContain container1 = new ZTLVContain();
            container1.parse(head.getValue());
            for (int i = 0; i < container1.itemCount(); i++) {
                // 获取SET
                ZTLVBase base = container1.getItem(i);
                // 获取SEQUENCE
                ZTLVBase baseSE = new ZTLVBase();
                baseSE.parse(base.getValue());
                ZTLVContain container3 = new ZTLVContain();
                container3.parse(baseSE.getValue());

                ZTLVBase bValue = container3.getItem(1);
                String value = parseValue(bValue);
                ZTLVBase bTAG = container3.getItem(0);
                setValue(value, bTAG);
            }
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private void setValue(String value, ZTLVBase bTAG) {
        byte[] bArr = bTAG.getValue().buffer();
        switch (bArr[2]) {
            case 3: {
                this.issuer = value;
                this.commonName = value;
            }
            break;
            case 6: {
                this.countryName = value;
            }
            break;
            case 10: {
                this.organizationName = value;
            }
            break;
        }
    }

    private String parseValue(ZTLVBase bValue) {
        byte[] bValu = bValue.getValue().buffer();
        int j = 0;
        for (; j < bValu.length; j++) {
            if (bValu[j] == 0x00) {
                break;
            }
        }
        byte[] newB = new byte[j];
        System.arraycopy(bValu, 0, newB, 0, newB.length);
        return new String(newB);
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
