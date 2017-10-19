package com.bol.util;

public class Thrower {

    /** Handy util method for cases when a checked exception should not have been defined checked */
    public static <A> A reThrow(Throwable exception) {
        class EvilThrower<T extends Throwable> {
            private void sneakyThrow(Throwable exception) throws T {
                throw (T) exception;
            }
        }
        new EvilThrower<RuntimeException>().sneakyThrow(exception);
        return null;    // will never happen, but compiler does not know that
    }
}
