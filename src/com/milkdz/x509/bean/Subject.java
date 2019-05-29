package com.milkdz.x509.bean;

import com.milkdz.x509.tlv.ZTLVBase;
import com.milkdz.x509.tlv.ZTLVContain;
import com.milkdz.x509.util.ByteArrayBuffer;

/**
 * Created by MilkZS on 2019/5/22 16:51
 */
public class Subject {

    private String countryName;
    private String organizationName;
    private String organizationnlUnitName;
    private String commonName;
    private String subject;

    public boolean parse(ByteArrayBuffer buffer) {
        try {

            ZTLVBase head = new ZTLVBase();
            head.parse(buffer);
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
                byte[] bValu = bValue.getValue().buffer();
                int j = 0;
                for (; j < bValu.length; j++) {
                    if (bValu[j] == 0x00) {
                        break;
                    }
                }
                byte[] newB = new byte[j];
                System.arraycopy(bValu, 0, newB, 0, newB.length);
                String value = new String(newB);

                ZTLVBase bTAG = container3.getItem(0);
                byte[] bArr = bTAG.getValue().buffer();
                switch (bArr[2]){
                    case 3:{
                        this.subject = value;
                        this.commonName = value;
                    }break;
                    case 11:{
                        this.organizationnlUnitName = value;
                    }break;
                    case 10:{
                        this.organizationName = value;
                    }break;
                    case 6:{
                        this.countryName = value;
                    }break;
                }
            }
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
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

    public String getOrganizationnlUnitName() {
        return organizationnlUnitName;
    }

    public String getCommonName() {
        return commonName;
    }
}
