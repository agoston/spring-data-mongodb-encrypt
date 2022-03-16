package com.bol.system;

import com.bol.crypt.CryptVault;
import org.bson.types.Binary;

import static org.assertj.core.api.Assertions.assertThat;

public class CryptAssert {

  private final CryptVault cryptVault;

  public CryptAssert(CryptVault cryptVault) {
    this.cryptVault = cryptVault;
  }

  /**
   * simplistic mongodb BSON serialization lengths:
   * - 10 bytes for wrapping BSONObject prefix
   * - 1 byte prefix before field name
   * - field name (1 byte/char)
   * - 1 byte 0-terminator after field name
   * - 4 byte prefix before field value
   * - field value (1byte/char)
   * - 1 byte 0-terminator after field value
   * - 2 bytes 0 terminator for wrapping BSONObject
   * <p>
   * (e.g. for a single primitive string, 12 extra bytes are added above its own length)
   */
  public void assertCryptLength(Object cryptedSecretBinary, int serializedLength) {
    assertThat(cryptedSecretBinary).isInstanceOf(Binary.class);

    Object cryptedSecretBytes = ((Binary) cryptedSecretBinary).getData();

    assertThat(cryptedSecretBytes).isInstanceOf(byte[].class);
    byte[] cryptedBytes = (byte[]) cryptedSecretBytes;

    int expectedCryptedLength = cryptVault.expectedCryptedLength(serializedLength);
    assertThat(cryptedBytes.length).isEqualTo(expectedCryptedLength);
  }

}
