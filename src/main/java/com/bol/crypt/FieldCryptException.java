package com.bol.crypt;

import java.util.ArrayList;
import java.util.List;

/** collect the whole tree in a single exception class for simplicity */
public class FieldCryptException extends RuntimeException {
    List<String> fields = new ArrayList<>();

    public FieldCryptException(String fieldName, Throwable e) {
        super(e);
        fields.add(fieldName);
    }

    public FieldCryptException chain(String fieldName) {
        if (fieldName != null && fieldName.length() > 0) fields.add(fieldName);
        return this;
    }

    @Override
    public String getMessage() {
        StringBuilder result = new StringBuilder();
        for (int i = fields.size() - 1; i >= 0; i--) {
            result.append(fields.get(i)).append('.');
        }
        return result.substring(0, result.length()-1);
    }
}
