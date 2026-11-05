package pk.ooad.ntd.domain;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AssetFactoryTest {

    private final AssetFactory factory = new AssetFactory();

    @Test
    @DisplayName("Positive: Factory creates correct concrete subclass for each AssetType")
    void testCreateAllAssetTypes() {
        NetworkAsset server = factory.create(AssetType.SERVER, "s-1", "Web", "10.0.0.1", 4);
        assertInstanceOf(Server.class, server);
        assertEquals(AssetType.SERVER, server.getType());
        assertEquals("s-1", server.getId());

        NetworkAsset ws = factory.create(AssetType.WORKSTATION, "w-1", "Finance PC", "10.0.0.2", 2);
        assertInstanceOf(Workstation.class, ws);
        assertEquals(AssetType.WORKSTATION, ws.getType());

        NetworkAsset router = factory.create(AssetType.ROUTER, "r-1", "Core Router", "10.0.0.254", 5);
        assertInstanceOf(Router.class, router);
        assertEquals(AssetType.ROUTER, router.getType());

        NetworkAsset iot = factory.create(AssetType.IOT_DEVICE, "i-1", "Thermostat", "10.0.0.60", 1);
        assertInstanceOf(IoTDevice.class, iot);
        assertEquals(AssetType.IOT_DEVICE, iot.getType());
    }

    @Test
    @DisplayName("Negative: Null parameters throw NullPointerException")
    void testCreateNullParameters() {
        assertThrows(NullPointerException.class, () ->
            factory.create(null, "id-1", "name", "10.0.0.1", 1)
        );
        assertThrows(NullPointerException.class, () ->
            factory.create(AssetType.SERVER, null, "name", "10.0.0.1", 1)
        );
    }
}

