package com.bol.system.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.util.ArrayList;
import java.util.List;

import static com.bol.system.model.PlainBean.MONGO_PLAINBEAN;

@Document(collection = MONGO_PLAINBEAN)
public class PlainBean {
  public static final String MONGO_PLAINBEAN = "plainBean";

  @Id public String id;

  @Field public String nonSensitiveData;
  @Field public String sensitiveData;

  public PlainSubBean singleSubBean;
  public List<PlainSubBean> subBeans = new ArrayList<>();

  public static class PlainSubBean {
    @Field public String nonSensitiveData;
    @Field public String sensitiveData;

    public PlainSubBean() {}
    public PlainSubBean(String nonSensitiveData, String sensitiveData) {
      this.nonSensitiveData = nonSensitiveData;
      this.sensitiveData = sensitiveData;
    }
  }
}

