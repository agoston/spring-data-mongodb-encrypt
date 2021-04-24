package com.bol.system.model;

import com.bol.secure.Encrypted;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.ArrayList;
import java.util.List;

import static com.bol.system.model.InitBean.MONGO_INITBEAN;

@Document(collection = MONGO_INITBEAN)
public class InitBean {
    public static final String MONGO_INITBEAN = "initbean";
    public static final String MONGO_SUB_BEANS = "subBeans";
    public static final String MONGO_DATA1 = "data1";
    public static final String MONGO_DATA2 = "data2";

    @Id
    public String id;
    @Encrypted
    public String data1;
    public List<InitSubBean> subBeans = new ArrayList<>();

    // this also tests non-public subdocuments
    public void addSubBean(String input) {
        InitSubBean initSubBean = new InitSubBean();
        initSubBean.data2 = input;
        subBeans.add(initSubBean);
    }
}

class InitSubBean {
    @Encrypted
    public String data2;
}
