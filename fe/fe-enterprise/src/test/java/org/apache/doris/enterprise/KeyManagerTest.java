package org.apache.doris.enterprise;

import org.apache.doris.common.Config;
import org.junit.Assert;
import org.junit.Test;
import org.junit.jupiter.api.BeforeEach;

public class KeyManagerTest {
    @Test
    public void testSetRootKeyByConfig() {
        Config.doris_tde_key_endpoint = "xxx";
        Config.doris_tde_key_region = "xxx";
        Config.doris_tde_key_provider = "aws_kms";
        Config.doris_tde_key_id = "";
        KeyManager manager = new KeyManager();
        IllegalArgumentException exception1 = Assert.assertThrows(
            IllegalArgumentException.class,
            () -> { manager.setRootKeyByConfig(); }
        );

        Assert.assertTrue(exception1.getMessage().contains("some of the doris_tde-related configurations are empty"));

        Config.doris_tde_key_endpoint = "xxx";
        Config.doris_tde_key_region = "xxx";
        Config.doris_tde_key_provider = "xxx_kms";
        Config.doris_tde_key_id = "key id";
        IllegalArgumentException exception2 = Assert.assertThrows(
            IllegalArgumentException.class,
            () -> { manager.setRootKeyByConfig(); }
        );

        Assert.assertTrue(exception2.getMessage().contains("doris_tde_key_provider"));
    }
}
