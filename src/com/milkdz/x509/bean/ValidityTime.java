package com.milkdz.x509.bean;

/**
 * Created by MilkZS on 2019/5/22 16:50
 */
public class ValidityTime {

    private String startTimeYMD;
    private String endTimeYMD;
    private String startTimeYMDHMS;
    private String endTimeYMDHMS;

    public void setStartTimeYMD(String startTimeYMD) {
        this.startTimeYMD = startTimeYMD;
    }

    public void setEndTimeYMD(String endTimeYMD) {
        this.endTimeYMD = endTimeYMD;
    }

    public String getStartTimeYMD() {
        return startTimeYMD;
    }

    public String getEndTimeYMD() {
        return endTimeYMD;
    }

    public String getStartTimeYMDHMS() {
        return startTimeYMDHMS;
    }

    public void setStartTimeYMDHMS(String startTimeYMDHMS) {
        this.startTimeYMDHMS = startTimeYMDHMS;
    }

    public String getEndTimeYMDHMS() {
        return endTimeYMDHMS;
    }

    public void setEndTimeYMDHMS(String endTimeYMDHMS) {
        this.endTimeYMDHMS = endTimeYMDHMS;
    }
}
