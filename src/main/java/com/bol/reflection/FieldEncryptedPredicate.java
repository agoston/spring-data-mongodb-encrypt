package com.bol.reflection;

import com.bol.secure.Encrypted;

import java.lang.reflect.Field;
import java.util.function.Predicate;

public interface FieldEncryptedPredicate extends Predicate<Field> {

  FieldEncryptedPredicate ANNOTATION_PRESENT = field -> field.isAnnotationPresent(Encrypted.class);

}
