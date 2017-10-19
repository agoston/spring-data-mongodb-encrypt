/*
 * Copyright (c) 2008-2014 MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.bol.secure;

import org.bson.BsonBinarySubType;

import java.io.Serializable;

/**
 * Generic binary holder.
 */
public class DynamicBinary implements Serializable {
    private static final long serialVersionUID = 7902997490338209467L;

    private final byte type;
    private final byte[] data;
    private final int offset;
    private final int length;

    /**
     * Creates a Binary object with the default binary type of 0
     *
     * @param data raw data
     */
    public DynamicBinary(final byte[] data, int offset, int length) {
        this(BsonBinarySubType.BINARY, data, offset, length);
    }

    /**
     * Creates a Binary with the specified type and data.
     *
     * @param type the binary type
     * @param data the binary data
     */
    public DynamicBinary(final BsonBinarySubType type, final byte[] data, int offset, int length) {
        this(type.getValue(), data, offset, length);
    }

    /**
     * Creates a Binary object
     *
     * @param type type of the field as encoded in BSON
     * @param data raw data
     */
    public DynamicBinary(final byte type, final byte[] data, int offset, int length) {
        this.type = type;
        this.data = data.clone();
        this.offset = offset;
        this.length = length;
    }

    /**
     * Get the binary sub type as a byte.
     *
     * @return the binary sub type as a byte.
     */
    public byte getType() {
        return type;
    }

    /**
     * Get a copy of the binary value.
     *
     * @return a copy of the binary value.
     */
    public byte[] getData() {
        byte[] result = new byte[length];
        System.arraycopy(data, offset, result, 0, length);
        return result;
    }

    /**
     * Get the length of the data.
     *
     * @return the length of the binary array.
     */
    public int length() {
        return length;
    }
}
