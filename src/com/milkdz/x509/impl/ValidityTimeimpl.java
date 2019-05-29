package com.milkdz.x509.impl;

import com.milkdz.x509.bean.ASNTAGBean;
import com.milkdz.x509.bean.ValidityTime;
import com.milkdz.x509.tlv.ZTLVBase;
import com.milkdz.x509.tlv.ZTLVContain;

/**
 * Created by zuoqi@bhz.com.cn on 2019/5/29 16:23
 */
public class ValidityTimeimpl {

    private ValidityTime validityTime;

    public ValidityTimeimpl() {
        this.validityTime = new ValidityTime();
    }

    /**
     * Validity ::= SEQUENCE {
     * notBefore      Time,
     * notAfter       Time }
     * Time ::= CHOICE {
     * utcTime        UTCTime,
     * generalTime    GeneralizedTime }
     */
    public boolean parse(ZTLVBase item) {
        if (item.getTag() != ASNTAGBean.TAG_ASN_SEQUENCE_AND_SEQUENCE_OF) return false;

        ZTLVContain container = new ZTLVContain();
        if (!container.parse(item.getValue())) return false;
        if (container.itemCount() != 2) return false;

        ZTLVBase notBefore = container.getItem(0);
        ZTLVBase notAfter = container.getItem(1);
        String startTime = new String(notBefore.getValue().buffer());
        String endTime = new String(notAfter.getValue().buffer());
        this.validityTime.setStartTimeYMD(parseTime(startTime));
        this.validityTime.setEndTimeYMD(parseTime(endTime));
        this.validityTime.setStartTimeYMDHMS(parseTimeMore(startTime));
        this.validityTime.setEndTimeYMDHMS(parseTimeMore(endTime));
        return true;
    }

    private String parseTime(String time) {
        return "20" + time.substring(0, 2) + "/" + time.substring(2, 4) + "/" + time.substring(4, 6);
    }

    private String parseTimeMore(String time) {
        return "20" + time.substring(0, 2) + "/" + time.substring(2, 4) + "/" + time.substring(4, 6)
                + " " + time.substring(6, 8) + ":" + time.substring(8, 10) + ":" + time.substring(10, 12);
    }

    public ValidityTime getValidityTime() {
        return validityTime;
    }
}
