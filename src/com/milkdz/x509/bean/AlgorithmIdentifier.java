package com.milkdz.x509.bean;

/**
 * Created by zuoqi@bhz.com.cn on 2019/5/29 16:43
 */
public class AlgorithmIdentifier {

    private int type;
    private String SimpleName;
    private String name;

    public int getType() {
        return type;
    }

    public void setType(int type) {
        this.type = type;
    }

    public String getSimpleName() {
        return SimpleName;
    }

    public void setSimpleName(String simpleName) {
        SimpleName = simpleName;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
