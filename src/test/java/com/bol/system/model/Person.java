package com.bol.system.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document
public class Person {
    public static final String MONGO_PERSON = "person";

    @Id
    public String id;
    public Ssn ssn;
}
